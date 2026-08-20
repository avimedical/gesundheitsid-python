"""Typed, validated access to the single `GESUNDHEITSID` Django setting.

Parsing happens eagerly, from `apps.GesundheitsIdConfig.ready()` -- a misconfigured relying
party must fail at process startup (missing key, malformed JWKS, non-P-256 key, ...), not
at the first `/auth` request a real insured person happens to trigger. `get_settings()` is
cached and invalidated on Django's `setting_changed` signal (the same pattern DRF's
`api_settings` uses), so the four keypairs are parsed once, not on every request.
"""

from __future__ import annotations

import base64
import functools
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from django.core.exceptions import ImproperlyConfigured
from django.dispatch import receiver
from django.test.signals import setting_changed
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from gesundheitsid.crypto import KeyPurpose, assert_p256, load_jwks, materialize_keypair
from gesundheitsid.errors import CryptoError
from gesundheitsid.federation import FederationMasterEnvironment

__all__ = [
    "DownstreamClient",
    "GesundheitsIdSettings",
    "StoreBackend",
    "get_settings",
]

_SETTING_NAME = "GESUNDHEITSID"

#: floor for GESUNDHEITSID["PAIRWISE_PEPPER"] -- an HMAC-SHA256 key this short would be a
#: false economy; this is a permanent secret (see GesundheitsIdSettings' docstring), so
#: there is no good reason to skimp on it.
_MIN_PAIRWISE_PEPPER_LENGTH = 32

#: GESUNDHEITSID["KEYS"] member name -> the KeyPurpose it must contain. Upper-snake to
#: match the rest of the settings dict's Django-convention naming, not KeyPurpose's own
#: (lower-snake) enum values.
_KEY_SETTING_NAMES: dict[str, KeyPurpose] = {
    "ENTITY_STATEMENT_SIG": KeyPurpose.ENTITY_STATEMENT_SIG,
    "MTLS_CLIENT": KeyPurpose.MTLS_CLIENT,
    "IDTOKEN_ENC": KeyPurpose.IDTOKEN_ENC,
    "DOWNSTREAM_SIG": KeyPurpose.DOWNSTREAM_SIG,
}

_VALID_AUTH_METHODS = ("none", "private_key_jwt")


class StoreBackend(StrEnum):
    """Which `Store` implementation `stores.get_store()` resolves to."""

    MEMORY = "memory"
    CACHE = "cache"
    DATABASE = "database"


@dataclass(frozen=True)
class DownstreamClient:
    """One client registered to sign in through this relying party's own downstream OIDC
    provider face. Config-driven, not a Django model -- see `views.py`'s module docstring
    for why the downstream token endpoint's client registry is deliberately not persisted
    the way Authlib's own `AuthorizationServer` would expect.
    """

    client_id: str
    redirect_uris: tuple[str, ...]
    token_endpoint_auth_method: str  # "none" or "private_key_jwt"
    jwks: dict | None  # required iff token_endpoint_auth_method == "private_key_jwt"


@dataclass(frozen=True)
class GesundheitsIdSettings:
    """Parsed, validated contents of the `GESUNDHEITSID` Django setting.

    `pairwise_pepper` is excluded from the auto-generated `repr()` (`field(repr=False)`)
    so it can never end up in a log line or traceback just because someone printed or
    logged this object -- it is the HMAC key behind every downstream `sub`
    (`views._pairwise_subject`), so its secrecy is exactly as load-bearing as a private
    signing key's. It is also, practically, PERMANENT once real accounts exist: rotating
    it changes every pairwise `sub` a downstream consumer has on file, silently unlinking
    every existing account. There is no rotation story for this value in this codebase;
    treat a change to it as equivalent to migrating every downstream account by hand.
    """

    issuer: str
    environment: FederationMasterEnvironment
    scopes: tuple[str, ...]
    redirect_uri: str
    organization_name: str
    client_name: str
    contacts: tuple[str, ...]
    entity_statement_sig_key: ECKey
    mtls_client_key: ECKey
    idtoken_enc_key: ECKey
    downstream_sig_key: ECKey
    mtls_tmp_dir: Path
    store_backend: StoreBackend
    cache_alias: str
    #: Opt out of the startup check that `STORE_BACKEND = "cache"` can pop atomically.
    #:
    #: The check exists because the non-atomic fallback in `CacheStore.pop` is not a weaker
    #: single-use guarantee but none at all: two requests racing on one authorization code both
    #: receive it. A cache alias that cannot do `GETDEL` is indistinguishable from one that can
    #: until two logins overlap, so it is refused by default rather than discovered in production.
    #:
    #: Set True only where that genuinely does not matter -- a test suite, or a single-threaded
    #: local run. Never in a deployment serving real logins; use Redis or `STORE_BACKEND =
    #: "database"` there instead.
    allow_non_atomic_store: bool
    trust_anchor_jwks: dict
    downstream_clients: tuple[DownstreamClient, ...]
    pairwise_pepper: str = field(repr=False)
    #: Explicit override for the Federation Master base URL, bypassing `environment.base_url`.
    #:
    #: `environment` stays a closed `TU|RU|PU` enum on purpose -- gematik's three real
    #: federation environments are the only hosts production config should ever be able to
    #: reach, and an enum can't drift onto an arbitrary host by typo the way a free-form URL
    #: setting could. This override exists solely so a local reference federation (see
    #: `docs/local-federation.md`) can be pointed at from outside that enum; it must be set
    #: explicitly (there is no environment value that implies it) and `TRUST_ANCHOR_JWKS`
    #: still pins the key that is trusted at whatever host this resolves to.
    federation_master_url: str | None = None

    @property
    def federation_master_base_url(self) -> str:
        """The Federation Master base URL this relying party actually talks to: the
        explicit override if one was configured, otherwise `environment.base_url`."""
        return self.federation_master_url if self.federation_master_url is not None else self.environment.base_url

    @functools.cached_property
    def mtls_paths(self) -> tuple[Path, Path]:
        """Materialize the mTLS client cert/key as PEM files under `mtls_tmp_dir`, once.

        Deliberately lazy, not done during startup validation: writing key material to
        disk should only happen for a process that actually makes an outbound mTLS call
        (a request handler), not for e.g. `manage.py purge_expired_gesundheitsid_entries`
        or any other command that loads this settings object but never touches the IdP.
        """
        cert_pem = _mtls_cert_pem(self.mtls_client_key)
        key_pem = _mtls_key_pem(self.mtls_client_key)
        return materialize_keypair(cert_pem, key_pem, self.mtls_tmp_dir)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> GesundheitsIdSettings:
        issuer = _require_https_url(raw, "ISSUER")
        redirect_uri = _require_https_url(raw, "REDIRECT_URI")
        environment = _require_environment(raw)
        scopes = _require_str_tuple(raw, "SCOPES", allow_empty=False)
        if "openid" not in scopes:
            raise ImproperlyConfigured(f"{_SETTING_NAME}['SCOPES'] must include 'openid', got {scopes!r}")
        organization_name = _require_str(raw, "ORGANIZATION_NAME")
        client_name = _require_str(raw, "CLIENT_NAME")
        contacts = _require_str_tuple(raw, "CONTACTS", allow_empty=False)

        keys_raw = _require(raw, "KEYS")
        if not isinstance(keys_raw, Mapping):
            raise ImproperlyConfigured(f"{_SETTING_NAME}['KEYS'] must be a mapping")
        loaded_keys = {
            setting_name: _load_single_key(setting_name, _require(keys_raw, setting_name))
            for setting_name in _KEY_SETTING_NAMES
        }
        _require_x5c(loaded_keys["MTLS_CLIENT"])

        mtls_tmp_dir = Path(_require_str(raw, "MTLS_TMP_DIR"))
        store_backend = _require_store_backend(raw)
        cache_alias = str(raw.get("CACHE_ALIAS", "default"))
        allow_non_atomic_store = bool(raw.get("ALLOW_NON_ATOMIC_STORE", False))
        trust_anchor_jwks = _require_jwks(raw, "TRUST_ANCHOR_JWKS")
        downstream_clients = _parse_downstream_clients(raw.get("DOWNSTREAM_CLIENTS", []))
        pairwise_pepper = _require_pairwise_pepper(raw)
        federation_master_url = _optional_https_url(raw, "FEDERATION_MASTER_URL")

        return cls(
            issuer=issuer,
            environment=environment,
            scopes=scopes,
            redirect_uri=redirect_uri,
            organization_name=organization_name,
            client_name=client_name,
            contacts=contacts,
            entity_statement_sig_key=loaded_keys["ENTITY_STATEMENT_SIG"],
            mtls_client_key=loaded_keys["MTLS_CLIENT"],
            idtoken_enc_key=loaded_keys["IDTOKEN_ENC"],
            downstream_sig_key=loaded_keys["DOWNSTREAM_SIG"],
            mtls_tmp_dir=mtls_tmp_dir,
            store_backend=store_backend,
            cache_alias=cache_alias,
            allow_non_atomic_store=allow_non_atomic_store,
            trust_anchor_jwks=trust_anchor_jwks,
            downstream_clients=downstream_clients,
            pairwise_pepper=pairwise_pepper,
            federation_master_url=federation_master_url,
        )


def _require(mapping: Mapping[str, object], key: str) -> object:
    if key not in mapping or mapping[key] in (None, ""):
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] is required")
    return mapping[key]


def _require_str(mapping: Mapping[str, object], key: str) -> str:
    value = _require(mapping, key)
    if not isinstance(value, str):
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must be a string, got {type(value).__name__}")
    return value


def _require_str_tuple(mapping: Mapping[str, object], key: str, *, allow_empty: bool) -> tuple[str, ...]:
    value = mapping.get(key)
    if value is None or not isinstance(value, list | tuple):
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must be a list of strings")
    if not value and not allow_empty:
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must not be empty")
    if not all(isinstance(item, str) and item for item in value):
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must contain only non-empty strings")
    return tuple(value)


def _require_https_url(mapping: Mapping[str, object], key: str) -> str:
    value = _require_str(mapping, key)
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.netloc:
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must be an https URL, got {value!r}")
    return value


def _optional_https_url(mapping: Mapping[str, object], key: str) -> str | None:
    """Like `_require_https_url`, but returns `None` when `key` is absent -- for settings
    that must be explicit https URLs *if given at all*, never a silent default."""
    value = mapping.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must be a string, got {type(value).__name__}")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.netloc:
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must be an https URL, got {value!r}")
    return value


def _require_environment(mapping: Mapping[str, object]) -> FederationMasterEnvironment:
    value = _require_str(mapping, "ENVIRONMENT")
    try:
        return FederationMasterEnvironment(value)
    except ValueError as exc:
        valid = ", ".join(member.value for member in FederationMasterEnvironment)
        raise ImproperlyConfigured(f"{_SETTING_NAME}['ENVIRONMENT'] must be one of {valid}, got {value!r}") from exc


def _require_store_backend(mapping: Mapping[str, object]) -> StoreBackend:
    value = _require_str(mapping, "STORE_BACKEND")
    try:
        return StoreBackend(value)
    except ValueError as exc:
        valid = ", ".join(member.value for member in StoreBackend)
        raise ImproperlyConfigured(f"{_SETTING_NAME}['STORE_BACKEND'] must be one of {valid}, got {value!r}") from exc


def _require_pairwise_pepper(mapping: Mapping[str, object]) -> str:
    value = _require_str(mapping, "PAIRWISE_PEPPER")
    if len(value) < _MIN_PAIRWISE_PEPPER_LENGTH:
        raise ImproperlyConfigured(
            f"{_SETTING_NAME}['PAIRWISE_PEPPER'] must be at least {_MIN_PAIRWISE_PEPPER_LENGTH} characters"
        )
    return value


def _require_jwks(mapping: Mapping[str, object], key: str) -> dict:
    value = _require(mapping, key)
    parsed = json.loads(value) if isinstance(value, str) else value
    if not isinstance(parsed, dict) or "keys" not in parsed:
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] must be a JWKS document (a dict with a 'keys' member)")
    try:
        load_jwks(parsed)
    except (JoseError, KeyError, TypeError, ValueError) as exc:
        raise ImproperlyConfigured(f"{_SETTING_NAME}['{key}'] is not a valid JWKS: {exc}") from exc
    return parsed


def _load_single_key(setting_name: str, raw: object) -> ECKey:
    """Parse one `GESUNDHEITSID['KEYS'][setting_name]` entry into an `ECKey`.

    Accepts either a bare JWK dict (a single key) or a JWKS document (`{"keys": [...]}`
    containing exactly one key) -- the latter is what `gesundheitsid_cli keygen` writes to
    disk for each purpose, via `crypto.private_jwks([key])`.
    """
    parsed = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(parsed, dict):
        raise ImproperlyConfigured(f"{_SETTING_NAME}['KEYS']['{setting_name}'] must be a JWK or JWKS mapping")

    if "keys" in parsed:
        try:
            keyset_keys = load_jwks(parsed).keys
        except (JoseError, KeyError, TypeError, ValueError) as exc:
            raise ImproperlyConfigured(f"{_SETTING_NAME}['KEYS']['{setting_name}'] is not a valid JWKS: {exc}") from exc
        if len(keyset_keys) != 1:
            raise ImproperlyConfigured(
                f"{_SETTING_NAME}['KEYS']['{setting_name}'] must contain exactly one key, got {len(keyset_keys)}"
            )
        key = keyset_keys[0]
    else:
        try:
            key = ECKey.import_key(parsed)
        except (JoseError, ValueError, TypeError) as exc:
            raise ImproperlyConfigured(f"{_SETTING_NAME}['KEYS']['{setting_name}'] is not a valid JWK: {exc}") from exc

    try:
        assert_p256(key)
    except CryptoError as exc:
        raise ImproperlyConfigured(f"{_SETTING_NAME}['KEYS']['{setting_name}']: {exc}") from exc
    return key


def _require_x5c(mtls_key: ECKey) -> None:
    if "x5c" not in mtls_key.as_dict(private=False):
        raise ImproperlyConfigured(
            f"{_SETTING_NAME}['KEYS']['MTLS_CLIENT'] must carry an 'x5c' certificate entry "
            "(see gesundheitsid.crypto.attach_x5c)"
        )


def _mtls_cert_pem(mtls_key: ECKey) -> bytes:
    """Re-render the mTLS key's `x5c` entry (a base64, RFC 4648-standard-encoded DER
    certificate per RFC 7517) as a PEM block `materialize_keypair` can write to disk."""
    x5c = mtls_key.as_dict(private=False)["x5c"]
    der = base64.b64decode(x5c[0])
    cert = x509.load_der_x509_certificate(der)
    return cert.public_bytes(Encoding.PEM)


def _mtls_key_pem(mtls_key: ECKey) -> bytes:
    private_key = mtls_key.private_key
    if private_key is None:
        raise ImproperlyConfigured(f"{_SETTING_NAME}['KEYS']['MTLS_CLIENT'] has no private key component")
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _parse_downstream_clients(raw: object) -> tuple[DownstreamClient, ...]:
    if not isinstance(raw, list | tuple):
        raise ImproperlyConfigured(f"{_SETTING_NAME}['DOWNSTREAM_CLIENTS'] must be a list")

    clients: list[DownstreamClient] = []
    for index, entry in enumerate(raw):
        label = f"{_SETTING_NAME}['DOWNSTREAM_CLIENTS'][{index}]"
        if not isinstance(entry, Mapping):
            raise ImproperlyConfigured(f"{label} must be a mapping")

        client_id = _require_str(entry, "CLIENT_ID")
        redirect_uris = _require_str_tuple(entry, "REDIRECT_URIS", allow_empty=False)
        auth_method = _require_str(entry, "TOKEN_ENDPOINT_AUTH_METHOD")
        if auth_method not in _VALID_AUTH_METHODS:
            raise ImproperlyConfigured(f"{label}['TOKEN_ENDPOINT_AUTH_METHOD'] must be one of {_VALID_AUTH_METHODS}")

        jwks = None
        if auth_method == "private_key_jwt":
            jwks = _require_jwks(entry, "JWKS")
        elif "JWKS" in entry:
            raise ImproperlyConfigured(
                f"{label}: JWKS is only meaningful for token_endpoint_auth_method=private_key_jwt"
            )

        clients.append(
            DownstreamClient(
                client_id=client_id,
                redirect_uris=redirect_uris,
                token_endpoint_auth_method=auth_method,
                jwks=jwks,
            )
        )
    return tuple(clients)


@functools.lru_cache(maxsize=1)
def get_settings() -> GesundheitsIdSettings:
    """Return the parsed, validated `GESUNDHEITSID` setting. Cached; see module docstring."""
    from django.conf import settings as django_settings

    raw = getattr(django_settings, _SETTING_NAME, None)
    if raw is None:
        raise ImproperlyConfigured(f"the {_SETTING_NAME} setting is required")
    if not isinstance(raw, Mapping):
        raise ImproperlyConfigured(f"the {_SETTING_NAME} setting must be a dict")
    return GesundheitsIdSettings.from_mapping(raw)


@receiver(setting_changed)
def _clear_settings_cache(*, setting: str, **kwargs: object) -> None:
    """Invalidate the cached settings whenever a test uses `override_settings`."""
    if setting == _SETTING_NAME:
        get_settings.cache_clear()

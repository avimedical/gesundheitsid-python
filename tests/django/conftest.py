"""Shared fixtures for the `django_gesundheitsid` test suite: a throwaway relying-party
key set, a cryptographically real fake TI-Föderation (Federation Master + one sectoral
IdP), and a `GESUNDHEITSID` settings dict wired to that fake federation's endpoints.

Deliberately not shared code with `tests/federation/conftest.py` / `tests/oidc/conftest.py`:
a Django settings dict needs the key material shaped as JSON-serializable JWKS dicts, not
bare `ECKey` objects, so the fixtures here build their own (structurally identical) fake
federation rather than importing the core test suite's.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
import respx
from django.urls import reverse
from joserfc.jwk import ECKey

from gesundheitsid.crypto import (
    KeyPurpose,
    attach_x5c,
    generate_p256_key,
    generate_self_signed_cert,
    private_jwks,
    public_jwks,
    sign_compact,
)
from gesundheitsid.federation import FederationMasterEnvironment
from gesundheitsid.oidc.pkce import generate_pkce

# `django_gesundheitsid.views._federation_master_client` builds its `FederationMasterClient`
# from `settings_.environment` (a `FederationMasterEnvironment`), which resolves to
# gematik's own real base URL -- there is no configurable override. So the fake federation
# below is mocked at that real TU base URL, not a made-up one, and `gesundheitsid_settings`
# always sets `ENVIRONMENT: "TU"` to match.
FM_BASE_URL = FederationMasterEnvironment.TU.base_url
IDP_ISSUER = "https://sektoraler-idp.gesundheitsid.invalid"
RP_ISSUER = "https://relying-party.gesundheitsid.invalid"
RP_REDIRECT_URI = f"{RP_ISSUER}/auth/callback"

PAR_ENDPOINT = f"{IDP_ISSUER}/par"
AUTHORIZATION_ENDPOINT = f"{IDP_ISSUER}/auth"
TOKEN_ENDPOINT = f"{IDP_ISSUER}/token"

DOWNSTREAM_CLIENT_ID = "downstream-public-client"
DOWNSTREAM_REDIRECT_URI = "https://downstream-client.invalid/callback"
DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID = "downstream-confidential-client"
DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI = "https://downstream-confidential-client.invalid/callback"

#: test-only pairwise pepper -- real deployments load this from a secret manager.
PAIRWISE_PEPPER = "test-only-pairwise-pepper-do-not-use-in-prod-00"

DEFAULT_LIFETIME_SECONDS = 3600


def _entity_statement_claims(
    *,
    iss: str,
    sub: str,
    jwks: dict,
    authority_hints: list[str] | None = None,
    metadata: dict | None = None,
    now: int | None = None,
    lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
) -> dict:
    current = now if now is not None else int(time.time())
    return {
        "iss": iss,
        "sub": sub,
        "iat": current,
        "exp": current + lifetime_seconds,
        "jwks": jwks,
        "authority_hints": authority_hints or [],
        "metadata": metadata or {},
    }


@dataclass
class RpKeys:
    entity_statement_sig: ECKey
    mtls_client: ECKey  # carries x5c
    idtoken_enc: ECKey
    downstream_sig: ECKey


@pytest.fixture
def rp_keys() -> RpKeys:
    es_sig = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    mtls = generate_p256_key(KeyPurpose.MTLS_CLIENT)
    cert = generate_self_signed_cert(mtls, subject_cn="relying-party.gesundheitsid.invalid")
    mtls = attach_x5c(mtls, cert)
    return RpKeys(
        entity_statement_sig=es_sig,
        mtls_client=mtls,
        idtoken_enc=generate_p256_key(KeyPurpose.IDTOKEN_ENC),
        downstream_sig=generate_p256_key(KeyPurpose.DOWNSTREAM_SIG),
    )


@dataclass
class FakeFederation:
    fm_signing_key: ECKey
    idp_key: ECKey
    subordinate_key: ECKey  # deliberately distinct from idp_key -- see tests/federation/conftest.py

    trust_anchor_jwks: dict

    fm_entity_configuration_token: str
    idp_entity_configuration_token: str
    subordinate_statement_token: str
    idps_list_token: str


@pytest.fixture
def fake_federation() -> FakeFederation:
    fm_signing_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    idp_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    subordinate_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)

    fm_claims = _entity_statement_claims(
        iss=FM_BASE_URL,
        sub=FM_BASE_URL,
        jwks=public_jwks([fm_signing_key]),
        # Endpoints are discovered from here, exactly as a real Federation Master publishes
        # them -- see tests/federation/conftest.py for why the paths are not invented.
        metadata={
            "federation_entity": {
                "federation_fetch_endpoint": f"{FM_BASE_URL}/federation_fetch_endpoint",
                "federation_list_endpoint": f"{FM_BASE_URL}/federation_list",
                "idp_list_endpoint": f"{FM_BASE_URL}/.well-known/idp_list",
            }
        },
    )
    fm_token = sign_compact(fm_claims, fm_signing_key, typ="entity-statement+jwt")

    idp_claims = _entity_statement_claims(
        iss=IDP_ISSUER,
        sub=IDP_ISSUER,
        jwks=public_jwks([idp_key]),
        authority_hints=[FM_BASE_URL],
        metadata={"openid_provider": {"issuer": IDP_ISSUER}},
    )
    idp_token = sign_compact(idp_claims, idp_key, typ="entity-statement+jwt")

    subordinate_claims = _entity_statement_claims(
        iss=FM_BASE_URL,
        sub=IDP_ISSUER,
        jwks=public_jwks([subordinate_key]),
        metadata={
            "openid_provider": {
                "issuer": IDP_ISSUER,
                "pushed_authorization_request_endpoint": PAR_ENDPOINT,
                "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                "token_endpoint": TOKEN_ENDPOINT,
            }
        },
    )
    subordinate_token = sign_compact(subordinate_claims, fm_signing_key, typ="entity-statement+jwt")

    idps_list_claims = {"idp_entity": [{"iss": IDP_ISSUER, "organization_name": "Test Insurer", "logo_uri": None}]}
    idps_list_token = sign_compact(idps_list_claims, fm_signing_key, typ="JWT")

    return FakeFederation(
        fm_signing_key=fm_signing_key,
        idp_key=idp_key,
        subordinate_key=subordinate_key,
        trust_anchor_jwks=public_jwks([fm_signing_key]),
        fm_entity_configuration_token=fm_token,
        idp_entity_configuration_token=idp_token,
        subordinate_statement_token=subordinate_token,
        idps_list_token=idps_list_token,
    )


@dataclass
class FederationRoutes:
    """Thin wiring over `respx_mock` -- mirrors `tests/federation/conftest.py`'s helper of
    the same name and shape."""

    respx_mock: respx.MockRouter
    fed: FakeFederation

    def fm_entity_configuration(self, *, status_code: int = 200) -> respx.Route:
        return self.respx_mock.get(f"{FM_BASE_URL}/.well-known/openid-federation").mock(
            return_value=httpx.Response(status_code, text=self.fed.fm_entity_configuration_token)
        )

    def idp_entity_configuration(self, *, status_code: int = 200) -> respx.Route:
        return self.respx_mock.get(f"{IDP_ISSUER}/.well-known/openid-federation").mock(
            return_value=httpx.Response(status_code, text=self.fed.idp_entity_configuration_token)
        )

    def subordinate_statement(self, *, status_code: int = 200) -> respx.Route:
        return self.respx_mock.get(f"{FM_BASE_URL}/federation_fetch_endpoint").mock(
            return_value=httpx.Response(status_code, text=self.fed.subordinate_statement_token)
        )

    def idps_list(self, *, status_code: int = 200, token: str | None = None) -> respx.Route:
        body = token if token is not None else self.fed.idps_list_token
        return self.respx_mock.get(f"{FM_BASE_URL}/.well-known/idp_list").mock(
            return_value=httpx.Response(status_code, text=body)
        )

    def par(
        self, *, request_uri: str = "urn:request_uri:test123", expires_in: int = 90, status_code: int = 201
    ) -> respx.Route:
        return self.respx_mock.post(PAR_ENDPOINT).mock(
            return_value=httpx.Response(status_code, json={"request_uri": request_uri, "expires_in": expires_in})
        )

    def happy_path(self) -> None:
        """Wire every endpoint a full `/auth` request touches."""
        self.fm_entity_configuration()
        self.idp_entity_configuration()
        self.subordinate_statement()
        self.idps_list()
        self.par()


@pytest.fixture
def federation_routes(respx_mock: respx.MockRouter, fake_federation: FakeFederation) -> FederationRoutes:
    return FederationRoutes(respx_mock=respx_mock, fed=fake_federation)


@pytest.fixture
def downstream_client_signing_key() -> ECKey:
    """The confidential downstream client's own keypair -- it signs `private_key_jwt`
    client assertions with this; only its public half is registered in
    `GESUNDHEITSID["DOWNSTREAM_CLIENTS"]`."""
    return generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)


@pytest.fixture
def gesundheitsid_settings(
    tmp_path: Path, rp_keys: RpKeys, fake_federation: FakeFederation, downstream_client_signing_key: ECKey
) -> dict:
    return {
        "ISSUER": RP_ISSUER,
        "ENVIRONMENT": "TU",
        "SCOPES": ["openid", "urn:telematik:display_name", "urn:telematik:versicherter"],
        "REDIRECT_URI": RP_REDIRECT_URI,
        "ORGANIZATION_NAME": "Test Relying Party",
        "CLIENT_NAME": "Test Relying Party",
        "CONTACTS": ["ops@relying-party.gesundheitsid.invalid"],
        "KEYS": {
            "ENTITY_STATEMENT_SIG": private_jwks([rp_keys.entity_statement_sig]),
            "MTLS_CLIENT": private_jwks([rp_keys.mtls_client]),
            "IDTOKEN_ENC": private_jwks([rp_keys.idtoken_enc]),
            "DOWNSTREAM_SIG": private_jwks([rp_keys.downstream_sig]),
        },
        "MTLS_TMP_DIR": str(tmp_path / "mtls"),
        "STORE_BACKEND": "memory",
        "TRUST_ANCHOR_JWKS": fake_federation.trust_anchor_jwks,
        "DOWNSTREAM_CLIENTS": [
            {
                "CLIENT_ID": DOWNSTREAM_CLIENT_ID,
                "REDIRECT_URIS": [DOWNSTREAM_REDIRECT_URI],
                "TOKEN_ENDPOINT_AUTH_METHOD": "none",
            },
            {
                "CLIENT_ID": DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
                "REDIRECT_URIS": [DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI],
                "TOKEN_ENDPOINT_AUTH_METHOD": "private_key_jwt",
                "JWKS": public_jwks([downstream_client_signing_key]),
            },
        ],
        "PAIRWISE_PEPPER": PAIRWISE_PEPPER,
    }


def build_auth_url(**overrides: str) -> str:
    """A `/auth` query string for the public (`none`-auth) downstream client, with fresh
    PKCE material. Callers needing the verifier later (to complete `/auth/token`) should
    generate their own `PkceMaterial` and pass `code_challenge`/`code_challenge_method`
    as overrides instead of relying on the one generated here.
    """
    pkce = generate_pkce()
    params = {
        "client_id": DOWNSTREAM_CLIENT_ID,
        "redirect_uri": DOWNSTREAM_REDIRECT_URI,
        "response_type": "code",
        "idp_iss": IDP_ISSUER,
        "state": "downstream-state-abc",
        "code_challenge": pkce.challenge,
        "code_challenge_method": pkce.method,
    }
    params.update(overrides)
    return f"{reverse('django_gesundheitsid:auth')}?{urlencode(params)}"


@pytest.fixture(autouse=True)
def _apply_gesundheitsid_settings(settings, gesundheitsid_settings: dict) -> None:
    """Every test in this package gets a GESUNDHEITSID pointed at its own fresh fake
    federation -- opting out (a bare, unconfigured RP) is what `test_conf.py` needs
    instead, and it calls `GesundheitsIdSettings.from_mapping` directly rather than going
    through Django settings at all.
    """
    settings.GESUNDHEITSID = gesundheitsid_settings


@pytest.fixture(autouse=True)
def _reset_shared_memory_store():
    """`stores.get_store()`'s `memory` backend is a deliberate module-level singleton
    (see its docstring: a fresh `InMemoryStore()` per call would forget everything
    immediately) -- correct for a real process, but it would otherwise leak cached
    Federation Master responses and stored sessions between tests. Reset it around every
    test instead of trying to make `get_store()` itself test-aware.
    """
    import django_gesundheitsid.stores as stores_module

    stores_module._memory_store = None
    yield
    stores_module._memory_store = None

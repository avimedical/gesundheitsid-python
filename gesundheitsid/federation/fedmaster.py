"""Client for gematik's Federation Master: the OpenID Federation trust anchor for the
TI-Föderation.

Every request in this module goes through a plain `httpx.Client` (`plain_client()` by
default), never the mTLS client from `crypto.mtls` -- gematik does not expect, and will
not trust, mTLS at the Federation Master; mTLS is reserved for a sectoral IdP's PAR/token
endpoints (see `crypto.mtls`'s own module docstring). Passing an mTLS client in here would
silently work over plain TLS and mislead a reader into thinking client-cert auth is in
effect for these calls, so keep the two call sites on separate clients.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from enum import StrEnum

import httpx

from gesundheitsid.crypto import load_jwks, plain_client, verify_compact
from gesundheitsid.errors import CryptoError, EntityStatementError, FederationMasterError
from gesundheitsid.federation.entity_statement import EntityStatement, verify_entity_statement
from gesundheitsid.storage import Store

__all__ = ["FederationMasterEnvironment", "FederationMasterClient", "SectoralIdp"]

_LOG = logging.getLogger(__name__)

#: entity configurations are cached for the shorter of their own exp and this cap
_ENTITY_CONFIG_CACHE_CAP_SECONDS = 24 * 3600
#: subordinate statements are cached for the shorter of their own exp and this cap
_SUBORDINATE_CACHE_CAP_SECONDS = 3600
#: the IdP list has no per-item exp to key off of, so it gets a flat TTL
_IDP_LIST_CACHE_TTL_SECONDS = 6 * 3600


class FederationMasterEnvironment(StrEnum):
    """gematik's three federation environments. See gemSpec_IDP_FedMaster."""

    TU = "TU"
    RU = "RU"
    PU = "PU"

    @property
    def base_url(self) -> str:
        return {
            FederationMasterEnvironment.TU: "https://app-test.federationmaster.de",
            FederationMasterEnvironment.RU: "https://app-ref.federationmaster.de",
            FederationMasterEnvironment.PU: "https://app.federationmaster.de",
        }[self]


@dataclass(frozen=True)
class SectoralIdp:
    """One entry from the Federation Master's idp_list endpoint: a health insurer's sectoral IdP."""

    issuer: str
    organization_name: str
    logo_uri: str | None
    #: True for a private insurer (PKV). 23 of the 129 production entries are PKV, so a picker that
    #: cannot tell them apart cannot explain why a privately insured user's experience differs.
    pkv: bool | None
    #: Which kind of subject the IdP authenticates. Every entry in all three environments
    #: currently says "IP" (insured person); the field exists at all because the
    #: TI-Foederation also covers Leistungserbringer identities, which carry other values.
    user_type_supported: str | None
    raw: dict


def _capped_ttl(exp: int, cap_seconds: int) -> int:
    """Seconds until `exp`, capped at `cap_seconds`, floored at 1 so a near-expired
    statement is still cached briefly rather than rejected by the Store outright."""
    remaining = exp - int(time.time())
    return max(1, min(remaining, cap_seconds))


#: Array key in the signed idp_list payload, verified against a running gsi-fedmaster 8.4.2. This
#: code previously looked for `idps`, which is simply not there - and the unit tests could not
#: catch it, because the fixture was built from the same assumption the parser made.
_IDP_LIST_ARRAY_KEY = "idp_entity"


def _parse_idps(claims: dict) -> list[SectoralIdp]:
    entries = claims.get(_IDP_LIST_ARRAY_KEY)
    if not isinstance(entries, list):
        raise FederationMasterError(f"idp_list payload is missing its {_IDP_LIST_ARRAY_KEY!r} array")

    idps = []
    for entry in entries:
        try:
            idps.append(
                SectoralIdp(
                    issuer=entry["iss"],
                    organization_name=entry["organization_name"],
                    logo_uri=entry.get("logo_uri"),
                    pkv=entry.get("pkv"),
                    user_type_supported=entry.get("user_type_supported"),
                    raw=entry,
                )
            )
        except (KeyError, TypeError) as exc:
            # One malformed row must not take the federation down: this same list is the SSRF allowlist
            # in views.auth, so raising would turn one bad entry into a total outage for every insurer.
            _LOG.warning("skipping malformed idp_list entry: %s", exc)

    # An empty result from a non-empty list is gematik changing the entry shape, not one bad row.
    # Returning [] would reject every login with "issuer is not in the federation" - a config error.
    if entries and not idps:
        raise FederationMasterError(f"every one of the {len(entries)} idp_list entries was malformed")
    return idps


class FederationMasterClient:
    """Talks to one Federation Master environment, caching responses through a `Store`.

    `trust_anchor_jwks` is the pinned public JWKS the caller trusts out-of-band (shipped
    with the relying party's config, not fetched at runtime) -- it is the sole root of
    trust for every method on this client. `store` is optional; without one, every call
    hits the network.
    """

    def __init__(
        self,
        base_url: str | FederationMasterEnvironment,
        *,
        trust_anchor_jwks: dict,
        http_client: httpx.Client | None = None,
        store: Store | None = None,
    ) -> None:
        if isinstance(base_url, FederationMasterEnvironment):
            self._base_url = base_url.base_url
        else:
            self._base_url = base_url.rstrip("/")
        self._trust_anchor_keys = load_jwks(trust_anchor_jwks)
        # never the mTLS client -- see module docstring.
        self._http = http_client if http_client is not None else plain_client()
        self._store = store

    @property
    def base_url(self) -> str:
        return self._base_url

    def _federation_endpoint(self, name: str) -> str:
        """Resolve one `federation_entity` endpoint from the trust anchor's own entity
        configuration.

        OpenID Federation 1.0 publishes these in `metadata.federation_entity` precisely so a
        relying party does not have to know an operator's URL layout, and the paths are NOT
        conventional: gematik's own reference Federation Master serves
        `/federation_fetch_endpoint`, `/federation_list` and `/.well-known/idp_list`. This code
        previously guessed `/federation/fetch`, `/federation/list` and `/federation/listidps`,
        which 404 against it -- so `list_idps()` (the insurer picker AND the allowlist that
        constrains `idp_iss` before any trust-chain resolution) and `fetch_subordinate_statement()`
        (the core of that resolution) could never have worked against a real Federation Master.
        Nothing caught it because the unit tests mock whichever URL the client asks for, which
        makes any path self-consistently "correct".

        Discovery costs nothing extra: the entity configuration is fetched and cached already.
        A Federation Master that does not advertise the endpoint is a hard failure rather than a
        fallback to a guess -- guessing is what produced the bug.
        """
        statement = self.entity_configuration()
        federation_entity = (statement.claims.get("metadata") or {}).get("federation_entity") or {}
        endpoint = federation_entity.get(name)
        if not isinstance(endpoint, str) or not endpoint:
            raise FederationMasterError(
                f"Federation Master at {self._base_url} does not advertise "
                f"metadata.federation_entity.{name}; cannot proceed without it"
            )
        return endpoint

    def entity_configuration(self) -> EntityStatement:
        """Fetch and verify the Federation Master's own entity configuration.

        Verified against the pinned `trust_anchor_jwks` supplied at construction time --
        never against keys embedded in the response itself, which would just be asking
        the response to vouch for itself.
        """
        cache_key = self._cache_key("entity_configuration")
        cached = self._cache_get(cache_key)
        if cached is not None:
            return EntityStatement.from_claims(json.loads(cached))

        url = f"{self._base_url}/.well-known/openid-federation"
        token = self._request(url)
        try:
            statement = verify_entity_statement(token, self._trust_anchor_keys)
        except EntityStatementError as exc:
            raise FederationMasterError(
                f"Federation Master entity configuration at {url} failed verification: {exc}"
            ) from exc

        self._cache_set(
            cache_key,
            json.dumps(statement.claims).encode(),
            _capped_ttl(statement.exp, _ENTITY_CONFIG_CACHE_CAP_SECONDS),
        )
        return statement

    def fetch_subordinate_statement(self, sub: str) -> EntityStatement:
        """Fetch and verify the Federation Master's subordinate statement about `sub`.

        These are the *authoritative* keys and metadata for `sub` in this federation --
        see `trust_chain`'s module docstring for why that matters. Verified against the
        Federation Master's own signing keys, established via `entity_configuration()`
        (itself pinned to the trust anchor); using any other keys here would verify
        nothing.
        """
        cache_key = self._cache_key(f"subordinate:{sub}")
        cached = self._cache_get(cache_key)
        if cached is not None:
            return EntityStatement.from_claims(json.loads(cached))

        fm_statement = self.entity_configuration()
        fm_keys = load_jwks(fm_statement.jwks)

        url = self._federation_endpoint("federation_fetch_endpoint")
        token = self._request(url, params={"iss": self._base_url, "sub": sub})
        try:
            statement = verify_entity_statement(token, fm_keys)
        except EntityStatementError as exc:
            raise FederationMasterError(
                f"subordinate statement for '{sub}' at {url} failed verification: {exc}"
            ) from exc

        self._cache_set(
            cache_key,
            json.dumps(statement.claims).encode(),
            _capped_ttl(statement.exp, _SUBORDINATE_CACHE_CAP_SECONDS),
        )
        return statement

    def list_members(self) -> list[str]:
        """The federation's member issuers, from its advertised federation_list_endpoint.
        Not cached: this list
        is comparatively cheap to fetch and has no per-response exp to key a TTL off of."""
        url = self._federation_endpoint("federation_list_endpoint")
        response_text = self._request(url)
        try:
            members = json.loads(response_text)
        except (TypeError, ValueError) as exc:
            raise FederationMasterError(f"federation list endpoint at {url} did not return valid JSON: {exc}") from exc
        if not isinstance(members, list):
            raise FederationMasterError(f"federation list endpoint at {url} did not return a JSON array")
        return members

    def list_idps(self) -> list[SectoralIdp]:
        """Fetch, verify, and parse gematik's signed list of sectoral IdPs.

        Always attempts a fresh fetch rather than reading the cache first -- this list
        drives an insurer picker, so a fresh copy should always win when the Federation
        Master is reachable. Only on failure to reach or verify a fresh copy does this
        fall back to the last successfully verified copy in the Store: a Federation
        Master outage must not turn into a broken login screen for every insured person
        trying to sign in. If there is no cached copy either, the failure propagates.
        """
        cache_key = self._cache_key("idps")
        url = f"{self._base_url}/<idp_list_endpoint unresolved>"

        try:
            fm_statement = self.entity_configuration()
            fm_keys = load_jwks(fm_statement.jwks)
            url = self._federation_endpoint("idp_list_endpoint")
            token = self._request(url)
            claims = verify_compact(token, fm_keys)
            idps = _parse_idps(claims)
        except (FederationMasterError, CryptoError) as exc:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return _parse_idps(json.loads(cached))
            raise FederationMasterError(
                f"failed to fetch idp list from {url} and no cached copy is available: {exc}"
            ) from exc

        self._cache_set(cache_key, json.dumps(claims).encode(), _IDP_LIST_CACHE_TTL_SECONDS)
        return idps

    def _request(self, url: str, **kwargs: object) -> str:
        try:
            response = self._http.get(url, **kwargs)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise FederationMasterError(f"request to {url} failed: {exc}") from exc
        return response.text

    def _cache_key(self, suffix: str) -> str:
        return f"gesundheitsid:fedmaster:{self._base_url}:{suffix}"

    def _cache_get(self, key: str) -> bytes | None:
        if self._store is None:
            return None
        return self._store.get(key)

    def _cache_set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        if self._store is None:
            return
        self._store.set(key, value, ttl_seconds)

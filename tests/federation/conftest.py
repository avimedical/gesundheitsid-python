"""A complete, cryptographically real fake TI-Föderation for federation tests: a trust
anchor, a Federation Master, and one leaf sectoral IdP -- built with the actual
`gesundheitsid.crypto` helpers so tests exercise genuine ES256 signatures, not stubs.

Deliberately, `subordinate_key` differs from `leaf_key`: the leaf's self-signed entity
configuration and the Federation Master's subordinate statement about it publish
different keys, exactly as a real deployment might mid-rotation. Tests that only ever see
one key for the leaf would not catch a relying party that trusts the wrong one.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

import httpx
import pytest
import respx
from joserfc.jwk import ECKey

from gesundheitsid.crypto import KeyPurpose, generate_p256_key, public_jwks, sign_compact

FM_BASE_URL = "https://fedmaster.example.com"
LEAF_ISSUER = "https://leaf-idp.example.com"

#: how long fixture statements are valid for, in seconds, from their build time
DEFAULT_LIFETIME_SECONDS = 3600

#: Endpoint paths exactly as gematik's reference Federation Master serves them (verified
#: against a running gsi-fedmaster 8.4.2). These fixtures previously invented
#: `/federation/fetch`, `/federation/list` and `/federation/listidps`, which agreed with the
#: client's own hardcoded guesses and therefore passed while every one of them 404s against a
#: real Federation Master. Endpoints are DISCOVERED from `metadata.federation_entity` below --
#: these constants only exist so the fixture serves them where the real thing does.
FM_FETCH_PATH = "/federation_fetch_endpoint"
FM_LIST_PATH = "/federation_list"
FM_IDP_LIST_PATH = "/.well-known/idp_list"

#: Array key in the signed idp_list payload, as gematik's reference emits it.
IDP_LIST_ARRAY_KEY = "idp_entity"


def entity_statement_claims(
    *,
    iss: str,
    sub: str,
    jwks: dict,
    authority_hints: list[str] | None = None,
    metadata: dict | None = None,
    now: int | None = None,
    lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
) -> dict:
    """Assemble the standard entity-statement claim set. Exposed for tests that need a
    one-off statement outside the default `fake_federation` fixture (e.g. tampered
    claims, a wrong-key signature)."""
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
class FakeFederation:
    fm_base_url: str
    leaf_issuer: str

    fm_signing_key: ECKey
    leaf_key: ECKey
    subordinate_key: ECKey  # deliberately distinct from leaf_key -- see module docstring

    trust_anchor_jwks: dict  # pinned out-of-band by a relying party; here == the FM's own public key

    fm_entity_configuration_token: str
    leaf_entity_configuration_token: str
    subordinate_statement_token: str

    leaf_exp: int
    subordinate_exp: int


@pytest.fixture
def fake_federation() -> FakeFederation:
    fm_signing_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    leaf_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    subordinate_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)

    trust_anchor_jwks = public_jwks([fm_signing_key])

    fm_claims = entity_statement_claims(
        iss=FM_BASE_URL,
        sub=FM_BASE_URL,
        jwks=public_jwks([fm_signing_key]),
        # A real Federation Master advertises where its endpoints are; the client discovers
        # them here rather than assuming a URL layout.
        metadata={
            "federation_entity": {
                "federation_fetch_endpoint": f"{FM_BASE_URL}{FM_FETCH_PATH}",
                "federation_list_endpoint": f"{FM_BASE_URL}{FM_LIST_PATH}",
                "idp_list_endpoint": f"{FM_BASE_URL}{FM_IDP_LIST_PATH}",
            }
        },
    )
    fm_token = sign_compact(fm_claims, fm_signing_key, typ="entity-statement+jwt")

    leaf_claims = entity_statement_claims(
        iss=LEAF_ISSUER,
        sub=LEAF_ISSUER,
        jwks=public_jwks([leaf_key]),
        authority_hints=[FM_BASE_URL],
        metadata={"openid_provider": {"issuer": LEAF_ISSUER}},
    )
    leaf_token = sign_compact(leaf_claims, leaf_key, typ="entity-statement+jwt")

    subordinate_claims = entity_statement_claims(
        iss=FM_BASE_URL,
        sub=LEAF_ISSUER,
        jwks=public_jwks([subordinate_key]),
        # Deliberately a partial overlay, like the real thing: gematik's reference returns only
        # `client_registration_types_supported` here, while the actual endpoints live in the
        # leaf's own configuration. `authoritative` is what the merge must let the superior win.
        metadata={"openid_provider": {"authoritative": True}},
    )
    subordinate_token = sign_compact(subordinate_claims, fm_signing_key, typ="entity-statement+jwt")

    return FakeFederation(
        fm_base_url=FM_BASE_URL,
        leaf_issuer=LEAF_ISSUER,
        fm_signing_key=fm_signing_key,
        leaf_key=leaf_key,
        subordinate_key=subordinate_key,
        trust_anchor_jwks=trust_anchor_jwks,
        fm_entity_configuration_token=fm_token,
        leaf_entity_configuration_token=leaf_token,
        subordinate_statement_token=subordinate_token,
        leaf_exp=leaf_claims["exp"],
        subordinate_exp=subordinate_claims["exp"],
    )


@dataclass
class FederationRoutes:
    """Thin wiring over `respx_mock` for the three endpoints a trust-chain resolution
    touches. Each method registers exactly one route; tests compose only the routes a
    given scenario actually reaches; the `respx_mock` fixture's `assert_all_mocked`
    default means any unregistered URL fails loudly instead of silently hitting the
    network."""

    respx_mock: respx.MockRouter
    fed: FakeFederation

    def fm_entity_configuration(self, *, token: str | None = None, status_code: int = 200) -> respx.Route:
        body = token if token is not None else self.fed.fm_entity_configuration_token
        return self.respx_mock.get(f"{self.fed.fm_base_url}/.well-known/openid-federation").mock(
            return_value=httpx.Response(status_code, text=body)
        )

    def leaf_entity_configuration(self, *, token: str | None = None, status_code: int = 200) -> respx.Route:
        body = token if token is not None else self.fed.leaf_entity_configuration_token
        return self.respx_mock.get(f"{self.fed.leaf_issuer}/.well-known/openid-federation").mock(
            return_value=httpx.Response(status_code, text=body)
        )

    def subordinate_statement(self, *, token: str | None = None, status_code: int = 200) -> respx.Route:
        body = token if token is not None else self.fed.subordinate_statement_token
        return self.respx_mock.get(f"{self.fed.fm_base_url}{FM_FETCH_PATH}").mock(
            return_value=httpx.Response(status_code, text=body)
        )

    def idps_list(self, *, token: str, status_code: int = 200) -> respx.Route:
        return self.respx_mock.get(f"{self.fed.fm_base_url}{FM_IDP_LIST_PATH}").mock(
            return_value=httpx.Response(status_code, text=token)
        )

    def members_list(self, *, members: list[str], status_code: int = 200) -> respx.Route:
        return self.respx_mock.get(f"{self.fed.fm_base_url}{FM_LIST_PATH}").mock(
            return_value=httpx.Response(status_code, text=json.dumps(members))
        )

    def happy_path(self) -> None:
        """Wire all three endpoints a full, successful trust-chain resolution touches."""
        self.fm_entity_configuration()
        self.leaf_entity_configuration()
        self.subordinate_statement()


@pytest.fixture
def federation_routes(respx_mock: respx.MockRouter, fake_federation: FakeFederation) -> FederationRoutes:
    return FederationRoutes(respx_mock=respx_mock, fed=fake_federation)

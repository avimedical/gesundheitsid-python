"""resolve_trust_chain: the six-step chain from a leaf sectoral IdP up to the pinned
Federation Master trust anchor, and a distinct TrustChainError per failure mode."""

from __future__ import annotations

import time

import httpx
import pytest

from gesundheitsid.crypto import KeyPurpose, generate_p256_key, public_jwks, sign_compact
from gesundheitsid.errors import TrustChainError
from gesundheitsid.federation.fedmaster import FederationMasterClient
from gesundheitsid.federation.trust_chain import resolve_trust_chain
from tests.federation.conftest import LEAF_ISSUER, FakeFederation, FederationRoutes, entity_statement_claims


def _client(fake_federation: FakeFederation) -> FederationMasterClient:
    return FederationMasterClient(fake_federation.fm_base_url, trust_anchor_jwks=fake_federation.trust_anchor_jwks)


def _resolve(fake_federation: FakeFederation, **kwargs: object):
    return resolve_trust_chain(
        subject_issuer=fake_federation.leaf_issuer,
        fedmaster_client=_client(fake_federation),
        **kwargs,
    )


@pytest.mark.parametrize(
    "issuer",
    [
        "http://idp.example.com",  # cleartext
        "http://169.254.169.254/latest/meta-data",  # cloud metadata endpoint
        "https://user:pw@idp.example.com",  # userinfo
        "https://idp.example.com?next=x",  # query string
        "https://idp.example.com#frag",  # fragment
        "https://idp.example.com/",  # trailing slash
        "not-a-url",
    ],
)
def test_rejects_unsafe_issuers_before_any_network_call(
    issuer: str, federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    """`idp_iss` is attacker-controlled, so a malformed issuer must fail before we fetch it.

    Asserting respx saw no call is the point: a shape check that still made the request
    would leave the SSRF surface wide open. This is not a full SSRF defence -- callers
    must also constrain idp_iss to the signed list_idps() allowlist -- but nothing here
    should ever reach the network.
    """
    federation_routes.happy_path()

    with pytest.raises(TrustChainError):
        resolve_trust_chain(subject_issuer=issuer, fedmaster_client=_client(fake_federation))

    assert not any(route.called for route in federation_routes.respx_mock.routes)


def test_happy_path_returns_the_subordinate_statements_keys_not_the_self_signed_ones(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.happy_path()

    chain = _resolve(fake_federation)

    leaf_own_jwks = public_jwks([fake_federation.leaf_key])
    subordinate_jwks = public_jwks([fake_federation.subordinate_key])

    # the whole point of the trust chain: authoritative keys come from the Federation
    # Master's subordinate statement, never the leaf's own self-signed configuration.
    assert chain.signing_keys == subordinate_jwks
    assert chain.signing_keys != leaf_own_jwks
    assert chain.subject == fake_federation.leaf_issuer
    assert chain.trust_anchor == fake_federation.fm_base_url
    assert chain.metadata == {"openid_provider": {"issuer": fake_federation.leaf_issuer, "authoritative": True}}
    assert chain.expires_at == fake_federation.subordinate_exp


def test_rejects_an_unreachable_leaf(federation_routes: FederationRoutes, fake_federation: FakeFederation) -> None:
    federation_routes.respx_mock.get(f"{fake_federation.leaf_issuer}/.well-known/openid-federation").mock(
        side_effect=httpx.ConnectError("connection refused")
    )

    with pytest.raises(TrustChainError, match="could not reach"):
        _resolve(fake_federation)


def test_rejects_a_bad_self_signature(federation_routes: FederationRoutes, fake_federation: FakeFederation) -> None:
    # publishes leaf_key in its jwks, but is actually signed with a different key --
    # verify_self_signed must catch this even though the claims themselves look fine.
    claims = entity_statement_claims(
        iss=fake_federation.leaf_issuer,
        sub=fake_federation.leaf_issuer,
        jwks=public_jwks([fake_federation.leaf_key]),
        authority_hints=[fake_federation.fm_base_url],
    )
    bad_token = sign_compact(claims, fake_federation.subordinate_key)
    federation_routes.leaf_entity_configuration(token=bad_token)

    with pytest.raises(TrustChainError, match="self-signed"):
        _resolve(fake_federation)


def test_rejects_a_leaf_missing_the_fm_from_authority_hints(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    claims = entity_statement_claims(
        iss=fake_federation.leaf_issuer,
        sub=fake_federation.leaf_issuer,
        jwks=public_jwks([fake_federation.leaf_key]),
        authority_hints=["https://some-other-federation.example.com"],
    )
    token = sign_compact(claims, fake_federation.leaf_key)
    federation_routes.leaf_entity_configuration(token=token)
    federation_routes.fm_entity_configuration()

    with pytest.raises(TrustChainError, match="authority_hints"):
        _resolve(fake_federation)


def test_rejects_when_the_fm_signature_does_not_match_the_pinned_trust_anchor(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration()
    federation_routes.fm_entity_configuration()  # signed by fm_signing_key

    # the client is pinned to a DIFFERENT trust anchor than the one that actually signed
    # the FM's entity configuration -- this must fail even though every signature is
    # otherwise individually valid.
    wrong_trust_anchor_jwks = public_jwks([fake_federation.leaf_key])
    client = FederationMasterClient(fake_federation.fm_base_url, trust_anchor_jwks=wrong_trust_anchor_jwks)

    with pytest.raises(TrustChainError, match="Federation Master"):
        resolve_trust_chain(subject_issuer=fake_federation.leaf_issuer, fedmaster_client=client)


def test_rejects_a_subordinate_statement_that_is_not_found(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration()
    federation_routes.fm_entity_configuration()
    federation_routes.subordinate_statement(status_code=404)

    with pytest.raises(TrustChainError, match="subordinate statement"):
        _resolve(fake_federation)


def test_rejects_a_subordinate_statement_signed_by_the_wrong_key(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration()
    federation_routes.fm_entity_configuration()
    claims = entity_statement_claims(
        iss=fake_federation.fm_base_url,
        sub=fake_federation.leaf_issuer,
        jwks=public_jwks([fake_federation.subordinate_key]),
    )
    wrong_key_token = sign_compact(claims, fake_federation.leaf_key)  # not the FM's key
    federation_routes.subordinate_statement(token=wrong_key_token)

    with pytest.raises(TrustChainError, match="subordinate statement"):
        _resolve(fake_federation)


def test_rejects_a_self_signed_config_whose_iss_does_not_match_its_sub(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    claims = entity_statement_claims(
        iss=fake_federation.leaf_issuer,
        sub="https://someone-else.example.com",
        jwks=public_jwks([fake_federation.leaf_key]),
        authority_hints=[fake_federation.fm_base_url],
    )
    token = sign_compact(claims, fake_federation.leaf_key)
    federation_routes.leaf_entity_configuration(token=token)

    with pytest.raises(TrustChainError, match="iss/sub"):
        _resolve(fake_federation)


def test_rejects_a_subordinate_statement_whose_sub_does_not_match_the_subject(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration()
    federation_routes.fm_entity_configuration()
    claims = entity_statement_claims(
        iss=fake_federation.fm_base_url,
        sub="https://a-different-leaf.example.com",
        jwks=public_jwks([fake_federation.subordinate_key]),
    )
    token = sign_compact(claims, fake_federation.fm_signing_key)
    federation_routes.subordinate_statement(token=token)

    with pytest.raises(TrustChainError, match="does not match subject"):
        _resolve(fake_federation)


def test_rejects_an_expired_self_signed_leaf_configuration(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration()

    with pytest.raises(TrustChainError, match="expired"):
        _resolve(fake_federation, now=fake_federation.leaf_exp + 1)


def test_rejects_an_expired_subordinate_statement(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.happy_path()

    with pytest.raises(TrustChainError, match="expired"):
        _resolve(fake_federation, now=fake_federation.subordinate_exp + 1)


def test_now_injection_is_deterministic_no_sleep_required(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.happy_path()

    # just inside the validity window -- must succeed without ever touching real time
    chain = _resolve(fake_federation, now=fake_federation.subordinate_exp - 1)
    assert chain.subject == fake_federation.leaf_issuer


# --------------------------------------------------------------------------------------
# signed_jwks_uri: a real sectoral IdP's id_token-signing key lives here, never in the subordinate
# statement's jwks, which only ever signs the entity statement. See trust_chain.py's docstring.

SIGNED_JWKS_URL = f"{LEAF_ISSUER}/signed-jwks"


def _leaf_entity_configuration_with_signed_jwks_uri(fake_federation: FakeFederation) -> str:
    claims = entity_statement_claims(
        iss=fake_federation.leaf_issuer,
        sub=fake_federation.leaf_issuer,
        jwks=public_jwks([fake_federation.leaf_key]),
        authority_hints=[fake_federation.fm_base_url],
        metadata={"openid_provider": {"issuer": fake_federation.leaf_issuer, "signed_jwks_uri": SIGNED_JWKS_URL}},
    )
    return sign_compact(claims, fake_federation.leaf_key, typ="entity-statement+jwt")


def _signed_jwks_token(*, iss: str, keys: list[dict], signing_key) -> str:
    payload = {"iss": iss, "iat": int(time.time()), "keys": keys}
    return sign_compact(payload, signing_key, typ="jwk-set+json")


def test_signed_jwks_uri_keys_are_folded_into_signing_keys(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    """The whole point: a real sectoral IdP's id_token-signing key is NOT the subordinate
    statement's key, and is only reachable this way -- see module docstring."""
    federation_routes.leaf_entity_configuration(token=_leaf_entity_configuration_with_signed_jwks_uri(fake_federation))
    federation_routes.fm_entity_configuration()
    federation_routes.subordinate_statement()

    operational_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    operational_jwk = public_jwks([operational_key])["keys"][0]
    # signed by subordinate_key -- the key the Federation Master actually vouches for --
    # not by leaf_key, which is only self-asserted.
    signed_jwks = _signed_jwks_token(
        iss=fake_federation.leaf_issuer, keys=[operational_jwk], signing_key=fake_federation.subordinate_key
    )
    federation_routes.respx_mock.get(SIGNED_JWKS_URL).mock(return_value=httpx.Response(200, text=signed_jwks))

    chain = _resolve(fake_federation)

    kids = {key["kid"] for key in chain.signing_keys["keys"]}
    assert operational_key.kid in kids, "signed_jwks_uri's key must be folded into signing_keys"
    assert fake_federation.subordinate_key.kid in kids, "the subordinate statement's own key must survive too"


def test_absent_signed_jwks_uri_leaves_signing_keys_unchanged(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    """No signed_jwks_uri (every other fixture in this file) must stay a pure no-op."""
    federation_routes.happy_path()

    chain = _resolve(fake_federation)

    assert chain.signing_keys == public_jwks([fake_federation.subordinate_key])


def test_rejects_a_signed_jwks_uri_signed_by_the_wrong_key(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration(token=_leaf_entity_configuration_with_signed_jwks_uri(fake_federation))
    federation_routes.fm_entity_configuration()
    federation_routes.subordinate_statement()

    operational_jwk = public_jwks([generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)])["keys"][0]
    # signed by leaf_key -- merely self-asserted, never vouched for by the fedmaster.
    signed_jwks = _signed_jwks_token(
        iss=fake_federation.leaf_issuer, keys=[operational_jwk], signing_key=fake_federation.leaf_key
    )
    federation_routes.respx_mock.get(SIGNED_JWKS_URL).mock(return_value=httpx.Response(200, text=signed_jwks))

    with pytest.raises(TrustChainError, match="signed_jwks_uri"):
        _resolve(fake_federation)


def test_rejects_a_signed_jwks_uri_with_mismatched_iss(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration(token=_leaf_entity_configuration_with_signed_jwks_uri(fake_federation))
    federation_routes.fm_entity_configuration()
    federation_routes.subordinate_statement()

    operational_jwk = public_jwks([generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)])["keys"][0]
    signed_jwks = _signed_jwks_token(
        iss="https://someone-else.example.com", keys=[operational_jwk], signing_key=fake_federation.subordinate_key
    )
    federation_routes.respx_mock.get(SIGNED_JWKS_URL).mock(return_value=httpx.Response(200, text=signed_jwks))

    with pytest.raises(TrustChainError, match="signed_jwks_uri"):
        _resolve(fake_federation)


def test_rejects_an_unreachable_signed_jwks_uri(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.leaf_entity_configuration(token=_leaf_entity_configuration_with_signed_jwks_uri(fake_federation))
    federation_routes.fm_entity_configuration()
    federation_routes.subordinate_statement()
    federation_routes.respx_mock.get(SIGNED_JWKS_URL).mock(side_effect=httpx.ConnectError("connection refused"))

    with pytest.raises(TrustChainError, match="could not fetch signed_jwks_uri"):
        _resolve(fake_federation)

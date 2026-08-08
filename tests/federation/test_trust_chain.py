"""resolve_trust_chain: the six-step chain from a leaf sectoral IdP up to the pinned
Federation Master trust anchor, and a distinct TrustChainError per failure mode."""

from __future__ import annotations

import httpx
import pytest

from gesundheitsid.crypto import public_jwks, sign_compact
from gesundheitsid.errors import TrustChainError
from gesundheitsid.federation.fedmaster import FederationMasterClient
from gesundheitsid.federation.trust_chain import resolve_trust_chain
from tests.federation.conftest import FakeFederation, FederationRoutes, entity_statement_claims


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

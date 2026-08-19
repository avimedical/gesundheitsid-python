"""FederationMasterClient: pinned-trust-anchor verification, Store-backed caching, and
list_idps's stale-on-failure fallback."""

from __future__ import annotations

import json
import time

import httpx
import pytest

from gesundheitsid.crypto import KeyPurpose, generate_p256_key, public_jwks, sign_compact
from gesundheitsid.errors import FederationMasterError
from gesundheitsid.federation.fedmaster import FederationMasterClient, FederationMasterEnvironment
from gesundheitsid.storage import InMemoryStore
from tests.federation.conftest import FM_LIST_PATH, IDP_LIST_ARRAY_KEY, FakeFederation, FederationRoutes


def _client(fake_federation: FakeFederation, **kwargs: object) -> FederationMasterClient:
    return FederationMasterClient(
        fake_federation.fm_base_url, trust_anchor_jwks=fake_federation.trust_anchor_jwks, **kwargs
    )


def test_federation_master_environment_base_urls() -> None:
    assert FederationMasterEnvironment.TU.base_url == "https://app-test.federationmaster.de"
    assert FederationMasterEnvironment.RU.base_url == "https://app-ref.federationmaster.de"
    assert FederationMasterEnvironment.PU.base_url == "https://app.federationmaster.de"


def test_client_accepts_an_environment_in_place_of_a_base_url(fake_federation: FakeFederation) -> None:
    client = FederationMasterClient(FederationMasterEnvironment.TU, trust_anchor_jwks=fake_federation.trust_anchor_jwks)
    assert client.base_url == "https://app-test.federationmaster.de"


def test_entity_configuration_verifies_against_the_pinned_trust_anchor(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration()
    client = _client(fake_federation)

    statement = client.entity_configuration()

    assert statement.iss == fake_federation.fm_base_url
    assert statement.sub == fake_federation.fm_base_url


def test_entity_configuration_rejects_a_statement_not_signed_by_the_pinned_trust_anchor(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    imposter_signing_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    imposter_claims = {
        "iss": fake_federation.fm_base_url,
        "sub": fake_federation.fm_base_url,
        "iat": int(time.time()),
        "exp": int(time.time()) + 100,
        "jwks": public_jwks([imposter_signing_key]),
        "authority_hints": [],
        "metadata": {},
    }
    # signed by a key other than the pinned trust anchor's -- e.g. an attacker who
    # controls the DNS/hosting for the FM's well-known URL but not its private key.
    imposter_token = sign_compact(imposter_claims, imposter_signing_key)
    federation_routes.fm_entity_configuration(token=imposter_token)

    client = _client(fake_federation)

    with pytest.raises(FederationMasterError):
        client.entity_configuration()


def test_entity_configuration_wraps_transport_failures_with_the_url(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration(status_code=503)
    client = _client(fake_federation)

    with pytest.raises(FederationMasterError, match="fedmaster.example.com"):
        client.entity_configuration()


def test_entity_configuration_is_cached_and_issues_no_second_http_request(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    route = federation_routes.fm_entity_configuration()
    client = _client(fake_federation, store=InMemoryStore())

    first = client.entity_configuration()
    second = client.entity_configuration()

    assert first.iss == second.iss
    assert route.call_count == 1


def test_fetch_subordinate_statement_returns_the_fm_signed_statement(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration()
    federation_routes.subordinate_statement()
    client = _client(fake_federation)

    statement = client.fetch_subordinate_statement(fake_federation.leaf_issuer)

    assert statement.iss == fake_federation.fm_base_url
    assert statement.sub == fake_federation.leaf_issuer
    assert statement.jwks == public_jwks([fake_federation.subordinate_key])


def test_fetch_subordinate_statement_rejects_one_signed_by_the_wrong_key(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration()
    wrong_key_token = sign_compact(
        {
            "iss": fake_federation.fm_base_url,
            "sub": fake_federation.leaf_issuer,
            "iat": int(time.time()),
            "exp": int(time.time()) + 100,
            "jwks": public_jwks([fake_federation.subordinate_key]),
            "authority_hints": [],
            "metadata": {},
        },
        fake_federation.leaf_key,  # signed by the leaf, not the Federation Master
    )
    federation_routes.subordinate_statement(token=wrong_key_token)
    client = _client(fake_federation)

    with pytest.raises(FederationMasterError):
        client.fetch_subordinate_statement(fake_federation.leaf_issuer)


def test_fetch_subordinate_statement_is_cached_and_issues_no_second_http_request(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration()
    subordinate_route = federation_routes.subordinate_statement()
    client = _client(fake_federation, store=InMemoryStore())

    client.fetch_subordinate_statement(fake_federation.leaf_issuer)
    client.fetch_subordinate_statement(fake_federation.leaf_issuer)

    assert subordinate_route.call_count == 1


def test_list_members_returns_the_parsed_json_array(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    # Discovery first: the list endpoint's URL comes from the Federation Master's own
    # metadata, not from a path this client made up.
    federation_routes.fm_entity_configuration()
    federation_routes.members_list(members=[fake_federation.leaf_issuer, fake_federation.fm_base_url])
    client = _client(fake_federation)

    members = client.list_members()

    assert members == [fake_federation.leaf_issuer, fake_federation.fm_base_url]


def test_list_members_rejects_a_non_array_response(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    # The entity configuration is needed even here: the list endpoint's URL is discovered
    # from it rather than assumed.
    federation_routes.fm_entity_configuration()
    federation_routes.respx_mock.get(f"{fake_federation.fm_base_url}{FM_LIST_PATH}").mock(
        return_value=httpx.Response(200, text=json.dumps({"not": "a list"}))
    )
    client = _client(fake_federation)

    with pytest.raises(FederationMasterError):
        client.list_members()


def _idps_token(fake_federation: FakeFederation, entries: list[dict]) -> str:
    return sign_compact({IDP_LIST_ARRAY_KEY: entries}, fake_federation.fm_signing_key)


def test_list_idps_returns_parsed_verified_entries(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration()
    token = _idps_token(
        fake_federation,
        [{"iss": "https://insurer-a.example.com", "organization_name": "Insurer A", "logo_uri": "https://a/logo.png"}],
    )
    federation_routes.idps_list(token=token)
    client = _client(fake_federation)

    idps = client.list_idps()

    assert len(idps) == 1
    assert idps[0].issuer == "https://insurer-a.example.com"
    assert idps[0].organization_name == "Insurer A"
    assert idps[0].logo_uri == "https://a/logo.png"
    assert idps[0].raw["iss"] == "https://insurer-a.example.com"


def test_list_idps_is_served_stale_when_the_federation_master_is_down(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration()
    good_token = _idps_token(
        fake_federation, [{"iss": "https://insurer-a.example.com", "organization_name": "Insurer A", "logo_uri": None}]
    )
    idps_route = federation_routes.idps_list(token=good_token)
    client = _client(fake_federation, store=InMemoryStore())

    primed = client.list_idps()
    assert primed[0].organization_name == "Insurer A"
    assert idps_route.call_count == 1

    # simulate a Federation Master outage on the idp-list endpoint specifically
    idps_route.mock(return_value=httpx.Response(503))

    during_outage = client.list_idps()

    assert during_outage == primed
    assert idps_route.call_count == 2  # a fresh fetch really was attempted, and it failed


def test_list_idps_raises_when_the_federation_master_is_down_and_there_is_no_cache(
    federation_routes: FederationRoutes, fake_federation: FakeFederation
) -> None:
    federation_routes.fm_entity_configuration()
    federation_routes.idps_list(token="irrelevant", status_code=503)
    client = _client(fake_federation)

    with pytest.raises(FederationMasterError):
        client.list_idps()

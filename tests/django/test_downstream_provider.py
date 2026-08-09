"""Discovery/jwks endpoints, `private_key_jwt` client authentication at `/auth/token`,
and the pairwise-subject property everything downstream (`patient`'s
`account_external_identity.pairwise_sub`, the Keycloak grant that binds a token to an
account) rests on: `sub` must be the SAME across separate logins for the same KVNR, and
DIFFERENT across distinct KVNRs. See `views._pairwise_subject`.
"""

from __future__ import annotations

import time

import respx
from django.urls import reverse
from joserfc.jwt import encode as jwt_encode

from gesundheitsid.crypto import KeyPurpose, generate_p256_key, load_jwks, public_jwks, verify_compact
from tests.django.conftest import (
    DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
    DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
    FakeFederation,
    FederationRoutes,
    RpKeys,
)
from tests.django.test_views_callback import _drive_full_flow, _token_form


def _token_endpoint_url() -> str:
    # Matches what `views.token()` computes via `request.build_absolute_uri(...)` for an
    # unconfigured Django test `Client` (default SERVER_NAME="testserver", scheme http) --
    # the client_assertion's `aud` must match this exactly, per RFC 7523 Section 3.
    return f"http://testserver{reverse('django_gesundheitsid:token')}"


def test_openid_configuration_advertises_all_endpoints(client, gesundheitsid_settings: dict) -> None:
    response = client.get(reverse("django_gesundheitsid:openid-configuration"))

    assert response.status_code == 200
    body = response.json()
    assert body["issuer"] == gesundheitsid_settings["ISSUER"]
    assert body["authorization_endpoint"].endswith(reverse("django_gesundheitsid:auth"))
    assert body["token_endpoint"].endswith(reverse("django_gesundheitsid:token"))
    assert body["jwks_uri"].endswith(reverse("django_gesundheitsid:jwks"))
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["id_token_signing_alg_values_supported"] == ["ES256"]
    # `sub` is an HMAC of the KVNR under a per-deployment pepper, so it is not globally
    # correlatable. Advertising "public" would tell clients the opposite of what is true.
    assert body["subject_types_supported"] == ["pairwise"]


def test_jwks_publishes_the_downstream_signing_keys_public_half(client, rp_keys: RpKeys) -> None:
    response = client.get(reverse("django_gesundheitsid:jwks"))

    assert response.status_code == 200
    body = response.json()
    assert body == public_jwks([rp_keys.downstream_sig])
    assert "d" not in body["keys"][0]  # never the private component


def test_downstream_ids_sub_is_stable_across_two_separate_logins_for_the_same_kvnr(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    downstream_keys = load_jwks(public_jwks([rp_keys.downstream_sig]))
    subs = []

    for _ in range(2):
        result = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock, kvnr="X111111111")
        response = client.post(
            reverse("django_gesundheitsid:token"), _token_form(result["downstream_code"], result["pkce_verifier"])
        )
        assert response.status_code == 200
        claims = verify_compact(response.json()["id_token"], downstream_keys)
        subs.append(claims["sub"])

    assert subs[0] == subs[1]


def test_downstream_id_token_carries_a_unique_jti_per_mint(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    """`sub` is stable on purpose; `jti` must not be, or it cannot identify one redemption.

    The downstream code is single-use, but the id_token it is exchanged for is a bearer artifact
    that stays valid for its whole `exp` window and carries nothing to say it has already been
    redeemed. A consumer treating it as proof of a login therefore needs a per-token identifier to
    remember. This asserts both halves: the claim is present, and two logins for the SAME patient
    (identical `sub`) still get different `jti`s -- a `jti` derived from the identity rather than
    the mint would look correct here and be useless for replay detection.
    """
    downstream_keys = load_jwks(public_jwks([rp_keys.downstream_sig]))
    tokens = []

    for _ in range(2):
        result = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock, kvnr="X111111111")
        response = client.post(
            reverse("django_gesundheitsid:token"), _token_form(result["downstream_code"], result["pkce_verifier"])
        )
        assert response.status_code == 200
        tokens.append(verify_compact(response.json()["id_token"], downstream_keys))

    assert tokens[0]["jti"]
    assert tokens[1]["jti"]
    assert tokens[0]["sub"] == tokens[1]["sub"]
    assert tokens[0]["jti"] != tokens[1]["jti"]


def test_downstream_ids_sub_differs_for_different_kvnrs(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    downstream_keys = load_jwks(public_jwks([rp_keys.downstream_sig]))

    result_a = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock, kvnr="X111111111")
    response_a = client.post(
        reverse("django_gesundheitsid:token"), _token_form(result_a["downstream_code"], result_a["pkce_verifier"])
    )
    claims_a = verify_compact(response_a.json()["id_token"], downstream_keys)

    result_b = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock, kvnr="X222222222")
    response_b = client.post(
        reverse("django_gesundheitsid:token"), _token_form(result_b["downstream_code"], result_b["pkce_verifier"])
    )
    claims_b = verify_compact(response_b.json()["id_token"], downstream_keys)

    assert claims_a["sub"] != claims_b["sub"]
    # neither the raw KVNR nor the sectoral IdP's own sub must leak through as `sub`
    assert claims_a["sub"] != "X111111111"
    assert claims_b["sub"] != "X222222222"


def _client_assertion(*, signing_key, client_id: str, token_endpoint: str, jti: str = "assertion-jti-1") -> str:
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "jti": jti,
        "iat": now,
        "exp": now + 60,
    }
    return jwt_encode({"alg": "ES256"}, claims, signing_key)


def test_private_key_jwt_client_authentication_happy_path(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
    downstream_client_signing_key,
) -> None:
    result = _drive_full_flow(
        client,
        federation_routes,
        fake_federation,
        rp_keys,
        respx_mock,
        client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
        redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
    )

    token_endpoint = _token_endpoint_url()
    assertion = _client_assertion(
        signing_key=downstream_client_signing_key,
        client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
        token_endpoint=token_endpoint,
    )

    response = client.post(
        reverse("django_gesundheitsid:token"),
        _token_form(
            result["downstream_code"],
            result["pkce_verifier"],
            client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
            redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=assertion,
        ),
    )

    assert response.status_code == 200, response.content


def test_private_key_jwt_client_authentication_rejects_a_bad_signature(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    result = _drive_full_flow(
        client,
        federation_routes,
        fake_federation,
        rp_keys,
        respx_mock,
        client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
        redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
    )

    token_endpoint = _token_endpoint_url()
    wrong_key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)  # not the client's registered key
    assertion = _client_assertion(
        signing_key=wrong_key, client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID, token_endpoint=token_endpoint
    )

    response = client.post(
        reverse("django_gesundheitsid:token"),
        _token_form(
            result["downstream_code"],
            result["pkce_verifier"],
            client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
            redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=assertion,
        ),
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_private_key_jwt_client_authentication_rejects_a_replayed_assertion(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
    downstream_client_signing_key,
) -> None:
    token_endpoint = _token_endpoint_url()
    assertion = _client_assertion(
        signing_key=downstream_client_signing_key,
        client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
        token_endpoint=token_endpoint,
        jti="the-same-jti-both-times",
    )

    first_login = _drive_full_flow(
        client,
        federation_routes,
        fake_federation,
        rp_keys,
        respx_mock,
        client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
        redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
    )
    first_response = client.post(
        reverse("django_gesundheitsid:token"),
        _token_form(
            first_login["downstream_code"],
            first_login["pkce_verifier"],
            client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
            redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=assertion,
        ),
    )
    assert first_response.status_code == 200

    second_login = _drive_full_flow(
        client,
        federation_routes,
        fake_federation,
        rp_keys,
        respx_mock,
        client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
        redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
    )
    second_response = client.post(
        reverse("django_gesundheitsid:token"),
        _token_form(
            second_login["downstream_code"],
            second_login["pkce_verifier"],
            client_id=DOWNSTREAM_PRIVATE_KEY_JWT_CLIENT_ID,
            redirect_uri=DOWNSTREAM_PRIVATE_KEY_JWT_REDIRECT_URI,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=assertion,  # the SAME assertion, replayed
        ),
    )

    assert second_response.status_code == 401
    assert second_response.json()["error"] == "invalid_client"

"""`GET /auth/callback` (the redirect URI registered with gematik) and the downstream
`POST /auth/token` exchange it feeds into.

`_drive_full_flow` runs a complete `/auth` -> (mocked) sectoral-IdP token exchange ->
`/auth/callback` round trip and returns everything a `/auth/token` test needs to finish
the downstream leg itself -- the single-use downstream code and the PKCE verifier that
matches the challenge `/auth` was called with.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx
import respx
from django.urls import reverse

from gesundheitsid.crypto import encrypt_id_token, load_jwks, public_jwks, sign_compact, verify_compact
from gesundheitsid.oidc.idtoken import REQUIRED_ACR
from gesundheitsid.oidc.pkce import generate_pkce
from tests.django.conftest import (
    DOWNSTREAM_CLIENT_ID,
    DOWNSTREAM_REDIRECT_URI,
    IDP_ISSUER,
    RP_ISSUER,
    TOKEN_ENDPOINT,
    FakeFederation,
    FederationRoutes,
    RpKeys,
    build_auth_url,
)


def _build_id_token(fake_federation: FakeFederation, rp_keys: RpKeys, *, nonce: str, kvnr: str = "X123456789") -> str:
    now = int(time.time())
    claims = {
        "iss": IDP_ISSUER,
        "aud": RP_ISSUER,
        "sub": "the-idp-subject",  # deliberately NOT what ends up as the downstream `sub`
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
        "acr": REQUIRED_ACR,
        "urn:telematik:claims:id": kvnr,
        "urn:telematik:claims:organization": "104212059",
        "urn:telematik:claims:display_name": "Erika Mustermann",
    }
    inner = sign_compact(claims, fake_federation.subordinate_key)
    return encrypt_id_token(inner, rp_keys.idtoken_enc)


def _drive_full_flow(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
    *,
    kvnr: str = "X123456789",
    client_id: str = DOWNSTREAM_CLIENT_ID,
    redirect_uri: str = DOWNSTREAM_REDIRECT_URI,
    auth_url_overrides: dict | None = None,
) -> dict:
    pkce = generate_pkce()
    federation_routes.fm_entity_configuration()
    federation_routes.idp_entity_configuration()
    federation_routes.subordinate_statement()
    federation_routes.idps_list()
    par_route = federation_routes.par()

    auth_response = client.get(
        build_auth_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=pkce.challenge,
            code_challenge_method=pkce.method,
            **(auth_url_overrides or {}),
        )
    )
    assert auth_response.status_code == 302

    posted = dict(parse_qsl(par_route.calls.last.request.content.decode()))
    upstream_state = posted["state"]
    upstream_nonce = posted["nonce"]

    id_token = _build_id_token(fake_federation, rp_keys, nonce=upstream_nonce, kvnr=kvnr)
    respx_mock.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            200, json={"access_token": "upstream-at", "token_type": "Bearer", "expires_in": 300, "id_token": id_token}
        )
    )

    callback_response = client.get(
        reverse("django_gesundheitsid:auth-callback"), {"code": "the-idp-code", "state": upstream_state}
    )
    assert callback_response.status_code == 302, callback_response.content

    parsed = urlsplit(callback_response["Location"])
    query = parse_qs(parsed.query)

    return {
        "downstream_code": query["code"][0],
        "downstream_state": query["state"][0],
        "pkce_verifier": pkce.verifier,
        "redirect_location": callback_response["Location"],
    }


def _token_form(downstream_code: str, pkce_verifier: str, **overrides: str) -> dict:
    form = {
        "grant_type": "authorization_code",
        "client_id": DOWNSTREAM_CLIENT_ID,
        "redirect_uri": DOWNSTREAM_REDIRECT_URI,
        "code": downstream_code,
        "code_verifier": pkce_verifier,
    }
    form.update(overrides)
    return form


def test_auth_callback_happy_path_redirects_to_downstream_client_with_code_and_state(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    result = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock)

    parsed = urlsplit(result["redirect_location"])
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == DOWNSTREAM_REDIRECT_URI
    assert result["downstream_state"] == "downstream-state-abc"
    assert result["downstream_code"]


def test_auth_callback_rejects_an_unknown_state(client) -> None:
    response = client.get(reverse("django_gesundheitsid:auth-callback"), {"code": "x", "state": "an-unknown-state"})
    assert response.status_code == 400


def test_auth_callback_requires_state(client) -> None:
    response = client.get(reverse("django_gesundheitsid:auth-callback"), {"code": "x"})
    assert response.status_code == 400


def test_auth_callback_rejects_non_get(client) -> None:
    response = client.post(reverse("django_gesundheitsid:auth-callback"))
    assert response.status_code == 405


def test_downstream_token_exchange_happy_path_issues_an_es256_id_token_with_claims(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    result = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock)

    response = client.post(
        reverse("django_gesundheitsid:token"), _token_form(result["downstream_code"], result["pkce_verifier"])
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"

    downstream_keys = load_jwks(public_jwks([rp_keys.downstream_sig]))
    claims = verify_compact(body["id_token"], downstream_keys)  # raises if not ES256/verifiable
    assert claims["iss"] == RP_ISSUER
    assert claims["aud"] == DOWNSTREAM_CLIENT_ID
    assert claims["urn:telematik:claims:id"] == "X123456789"
    assert claims["urn:telematik:claims:display_name"] == "Erika Mustermann"


def test_downstream_code_is_single_use(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    result = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock)
    form = _token_form(result["downstream_code"], result["pkce_verifier"])

    first = client.post(reverse("django_gesundheitsid:token"), form)
    second = client.post(reverse("django_gesundheitsid:token"), form)

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_downstream_token_exchange_rejects_a_mismatched_redirect_uri(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    result = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock)
    form = _token_form(
        result["downstream_code"],
        result["pkce_verifier"],
        redirect_uri="https://not-the-redirect-uri-used-at-auth.invalid",
    )

    response = client.post(reverse("django_gesundheitsid:token"), form)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_downstream_token_exchange_rejects_a_wrong_pkce_verifier(
    client,
    federation_routes: FederationRoutes,
    fake_federation: FakeFederation,
    rp_keys: RpKeys,
    respx_mock: respx.MockRouter,
) -> None:
    result = _drive_full_flow(client, federation_routes, fake_federation, rp_keys, respx_mock)
    form = _token_form(result["downstream_code"], "the-wrong-verifier-entirely")

    response = client.post(reverse("django_gesundheitsid:token"), form)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"

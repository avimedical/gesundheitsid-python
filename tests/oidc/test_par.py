"""push_authorization_request (RFC 9126) and build_authorization_url against a fake
sectoral IdP's PAR/authorization endpoints."""

from __future__ import annotations

from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from gesundheitsid.errors import ProtocolError
from gesundheitsid.oidc.par import build_authorization_url, push_authorization_request
from gesundheitsid.oidc.pkce import generate_pkce, generate_state
from tests.oidc.conftest import (
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    PAR_ENDPOINT,
    REDIRECT_URI,
    FakeIdp,
)

_NONCE = "the-nonce"
_SCOPES = ["openid", "urn:telematik:versicherter"]


def _push(fake_idp: FakeIdp, http_client: httpx.Client, **overrides: object):
    kwargs: dict[str, object] = {
        "trust_chain": fake_idp.trust_chain,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scopes": _SCOPES,
        "pkce": generate_pkce(),
        "state": generate_state(),
        "nonce": _NONCE,
        "http_client": http_client,
    }
    kwargs.update(overrides)
    return push_authorization_request(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("status_code", [200, 201])
def test_push_authorization_request_happy_path(
    status_code: int, respx_mock: respx.MockRouter, fake_idp: FakeIdp
) -> None:
    respx_mock.post(PAR_ENDPOINT).mock(
        return_value=httpx.Response(status_code, json={"request_uri": "urn:request_uri:abc123", "expires_in": 90})
    )

    with httpx.Client() as http_client:
        result = _push(fake_idp, http_client)

    assert result.request_uri == "urn:request_uri:abc123"
    assert result.expires_in == 90


def test_push_authorization_request_posts_exactly_the_documented_form_fields(
    respx_mock: respx.MockRouter, fake_idp: FakeIdp
) -> None:
    route = respx_mock.post(PAR_ENDPOINT).mock(
        return_value=httpx.Response(201, json={"request_uri": "urn:request_uri:abc123", "expires_in": 90})
    )
    pkce = generate_pkce()
    state = generate_state()

    with httpx.Client() as http_client:
        _push(fake_idp, http_client, pkce=pkce, state=state)

    assert route.called
    request = route.calls.last.request
    posted = dict(parse_qsl(request.content.decode("utf-8")))

    assert posted == {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(_SCOPES),
        "code_challenge": pkce.challenge,
        "code_challenge_method": "S256",
        "nonce": _NONCE,
        "state": state,
        "acr_values": "gematik-ehealth-loa-high",
    }


def test_push_authorization_request_raises_protocol_error_on_non_2xx(
    respx_mock: respx.MockRouter, fake_idp: FakeIdp
) -> None:
    respx_mock.post(PAR_ENDPOINT).mock(return_value=httpx.Response(400, json={"error": "invalid_request"}))

    with httpx.Client() as http_client, pytest.raises(ProtocolError) as exc_info:
        _push(fake_idp, http_client)

    assert "400" in str(exc_info.value)


def test_build_authorization_url_shape(fake_idp: FakeIdp) -> None:
    url = build_authorization_url(fake_idp.trust_chain, CLIENT_ID, "urn:request_uri:abc123")

    assert url == (
        f"{AUTHORIZATION_ENDPOINT}?client_id=https%3A%2F%2Ffachdienst.example.com&"
        "request_uri=urn%3Arequest_uri%3Aabc123"
    )

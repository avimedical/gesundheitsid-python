"""exchange_code: authorization-code exchange at a fake sectoral IdP's token endpoint."""

from __future__ import annotations

import httpx
import pytest
import respx

from gesundheitsid.errors import ProtocolError
from gesundheitsid.oidc.pkce import generate_pkce
from gesundheitsid.oidc.token import exchange_code
from tests.oidc.conftest import CLIENT_ID, REDIRECT_URI, TOKEN_ENDPOINT, FakeIdp


def test_exchange_code_happy_path(respx_mock: respx.MockRouter, fake_idp: FakeIdp) -> None:
    respx_mock.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json={
                "id_token": "the.id.token",
                "access_token": "the-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
            },
        )
    )

    with httpx.Client() as http_client:
        result = exchange_code(
            trust_chain=fake_idp.trust_chain,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code="the-auth-code",
            pkce=generate_pkce(),
            http_client=http_client,
        )

    assert result.id_token == "the.id.token"
    assert result.access_token == "the-access-token"
    assert result.token_type == "Bearer"
    assert result.expires_in == 300
    assert result.raw["id_token"] == "the.id.token"


def test_exchange_code_oauth2_error_body_surfaces_error_and_description(
    respx_mock: respx.MockRouter, fake_idp: FakeIdp
) -> None:
    respx_mock.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant", "error_description": "code has expired"})
    )

    with httpx.Client() as http_client, pytest.raises(ProtocolError) as exc_info:
        exchange_code(
            trust_chain=fake_idp.trust_chain,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code="stale-code",
            pkce=generate_pkce(),
            http_client=http_client,
        )

    message = str(exc_info.value)
    assert "invalid_grant" in message
    assert "code has expired" in message

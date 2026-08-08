"""Authorization code exchange at a sectoral IdP's `token_endpoint`.

Same client authentication and same connection as the PAR call: `self_signed_tls_client_
auth` via the mTLS client, no client_secret or client_assertion. `http_client` must
therefore be the identical mTLS client used for `push_authorization_request` -- see
`gesundheitsid.oidc.par` and `gesundheitsid.crypto.mtls`'s module docstring.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from gesundheitsid.errors import ProtocolError
from gesundheitsid.federation.trust_chain import TrustChain
from gesundheitsid.oidc.pkce import PkceMaterial

__all__ = ["TokenResponse", "exchange_code"]


@dataclass(frozen=True)
class TokenResponse:
    """A successful token response. `raw` is the complete decoded JSON body, for any
    field (e.g. `refresh_token`) this dataclass does not surface explicitly."""

    id_token: str
    access_token: str
    token_type: str
    expires_in: int
    raw: dict


def exchange_code(
    *,
    trust_chain: TrustChain,
    client_id: str,
    redirect_uri: str,
    code: str,
    pkce: PkceMaterial,
    http_client: httpx.Client,
) -> TokenResponse:
    """Exchange an authorization `code` for tokens at the IdP behind `trust_chain`.

    `pkce.verifier` here must be the same `PkceMaterial` whose `.challenge` was pushed in
    `push_authorization_request` -- the IdP recomputes SHA256(verifier) and compares it
    against the challenge it received during PAR, per RFC 7636.
    """
    metadata = trust_chain.metadata.get("openid_provider") or {}
    endpoint = metadata.get("token_endpoint")
    if not endpoint:
        raise ProtocolError(f"trust chain for '{trust_chain.subject}' has no token_endpoint")

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": pkce.verifier,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }

    try:
        response = http_client.post(endpoint, data=form)
    except httpx.HTTPError as exc:
        raise ProtocolError(f"token request to {endpoint} failed: {exc}") from exc

    try:
        body = response.json()
    except ValueError as exc:
        raise ProtocolError(f"token response from {endpoint} is not valid JSON: {exc}") from exc

    if response.status_code != 200:
        # RFC 6749 Section 5.2: an OAuth2 error body carries `error` and, usually,
        # `error_description` -- surface both explicitly rather than just the raw status,
        # since the description is normally the only clue a caller gets about *why*.
        error = body.get("error") if isinstance(body, dict) else None
        description = body.get("error_description") if isinstance(body, dict) else None
        if error is not None:
            raise ProtocolError(
                f"token request to {endpoint} failed: error={error!r}, error_description={description!r}"
            )
        raise ProtocolError(f"token request to {endpoint} failed with status {response.status_code}: {response.text}")

    id_token = body.get("id_token")
    if not id_token:
        raise ProtocolError(f"token response from {endpoint} is missing id_token: {body}")

    return TokenResponse(
        id_token=id_token,
        access_token=body.get("access_token"),
        token_type=body.get("token_type"),
        expires_in=body.get("expires_in"),
        raw=body,
    )

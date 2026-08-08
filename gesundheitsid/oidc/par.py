"""RFC 9126 Pushed Authorization Request against a sectoral IdP's `pushed_authorization_
request_endpoint`, and building the resulting browser redirect.

Client authentication here is `self_signed_tls_client_auth`, not a client_secret or
client_assertion -- so `http_client` MUST be the mTLS client from
`gesundheitsid.crypto.mtls_client`, presenting this relying party's own client
certificate, never `plain_client()`. See `gesundheitsid.crypto.mtls`'s module docstring
for why the two clients must stay on separate connection pools.

The IdP's endpoints come from `trust_chain.metadata["openid_provider"]` -- the Federation
Master's subordinate statement about the IdP, never anything the IdP might claim about
itself out of band.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from gesundheitsid.errors import ProtocolError
from gesundheitsid.federation.trust_chain import TrustChain
from gesundheitsid.oidc.pkce import PkceMaterial

__all__ = ["ParResponse", "push_authorization_request", "build_authorization_url"]

#: gematik's wiki documents a 90-second lifetime for the `request_uri` PAR returns --
#: callers must complete the browser redirect (build_authorization_url -> the IdP) well
#: inside this window, not queue it or hand it to a background job.
REQUEST_URI_EXPIRY_SECONDS = 90


@dataclass(frozen=True)
class ParResponse:
    """A successful PAR response: the one-time `request_uri` to redirect the browser to,
    and how many seconds it stays valid for (see `REQUEST_URI_EXPIRY_SECONDS`)."""

    request_uri: str
    expires_in: int


def _provider_metadata(trust_chain: TrustChain) -> dict:
    metadata = trust_chain.metadata.get("openid_provider")
    if not metadata:
        raise ProtocolError(f"trust chain for '{trust_chain.subject}' carries no openid_provider metadata")
    return metadata


def push_authorization_request(
    *,
    trust_chain: TrustChain,
    client_id: str,
    redirect_uri: str,
    scopes: Iterable[str],
    pkce: PkceMaterial,
    state: str,
    nonce: str,
    http_client: httpx.Client,
    acr_values: str = "gematik-ehealth-loa-high",
) -> ParResponse:
    """POST a Pushed Authorization Request (RFC 9126) to the IdP behind `trust_chain`.

    `http_client` is required and MUST be an mTLS client (`gesundheitsid.crypto.
    mtls_client`) presenting this relying party's client certificate -- see the module
    docstring. gematik's documented response is HTTP 201, but 200 is also accepted since
    real sectoral IdP implementations have been observed to differ; any other status
    raises `ProtocolError` carrying both the status code and response body.
    """
    metadata = _provider_metadata(trust_chain)
    endpoint = metadata.get("pushed_authorization_request_endpoint")
    if not endpoint:
        raise ProtocolError(f"trust chain for '{trust_chain.subject}' has no pushed_authorization_request_endpoint")

    form = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "code_challenge": pkce.challenge,
        "code_challenge_method": pkce.method,
        "nonce": nonce,
        "state": state,
        "acr_values": acr_values,
    }

    try:
        response = http_client.post(endpoint, data=form)
    except httpx.HTTPError as exc:
        raise ProtocolError(f"PAR request to {endpoint} failed: {exc}") from exc

    if response.status_code not in (200, 201):
        raise ProtocolError(f"PAR request to {endpoint} failed with status {response.status_code}: {response.text}")

    try:
        body = response.json()
    except ValueError as exc:
        raise ProtocolError(f"PAR response from {endpoint} is not valid JSON: {exc}") from exc

    request_uri = body.get("request_uri")
    expires_in = body.get("expires_in")
    if not request_uri or expires_in is None:
        raise ProtocolError(f"PAR response from {endpoint} is missing request_uri/expires_in: {body}")

    return ParResponse(request_uri=request_uri, expires_in=expires_in)


def build_authorization_url(trust_chain: TrustChain, client_id: str, request_uri: str) -> str:
    """Build the browser redirect URL for a `request_uri` obtained from
    `push_authorization_request`.

    The result is only valid for as long as `request_uri` itself is -- see
    `REQUEST_URI_EXPIRY_SECONDS` -- so the redirect must happen immediately, not be
    stored for later use.
    """
    metadata = _provider_metadata(trust_chain)
    endpoint = metadata.get("authorization_endpoint")
    if not endpoint:
        raise ProtocolError(f"trust chain for '{trust_chain.subject}' has no authorization_endpoint")

    query = urlencode({"client_id": client_id, "request_uri": request_uri})
    return f"{endpoint}?{query}"

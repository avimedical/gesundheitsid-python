"""The OIDC data plane -- PAR, authorization, token exchange, and encrypted id_token
parsing -- against gematik's real reference sectoral IdP (gsi-server), not `respx` mocks.

Before these tests existed, this path had NEVER run against a real counterparty:
`tests/oidc/test_par.py`/`test_token.py` mock `httpx.Client()` directly, never
`gesundheitsid.crypto.mtls.mtls_client`, so no real mTLS handshake and no real gsi-server
response had ever been exercised. Getting here (see this repo's git history around this
file) found three real defects that every one of those mocked tests was structurally
unable to catch: `decrypt_id_token` rejected gemSpec_IDP_Sek's own `version` JWE header
extension; `TrustChain.signing_keys` never included the key gsi-server ACTUALLY signs an
id_token with (`signed_jwks_uri`, a separate hop from the subordinate statement's key);
and `verify_compact`'s default header-size cap (512 bytes) was too small for a real
x5c-bearing JWS header. All three are fixed in `gesundheitsid/`, not worked around here.

TWO constraints shape every test below, both explained fully in
docs/local-federation.md:

- **Hardcoded RP metadata.** `EntityStatementFederationMemberBuilder.
  buildMetadataForRelyingParty` hardcodes `redirect_uris`/`scope` into the statement it
  issues about ANY relying party. `REDIRECT_URI`/`SCOPES` in `conftest.py` are that
  hardcoded set, not this project's own preference -- using anything else makes every
  PAR fail with `invalid_scope`/an unregistered redirect_uri, regardless of what this
  relying party's own real `GESUNDHEITSID` settings say.
- **No real browser, no real authenticator.** `redirect.testsuite.gsi` does not exist and
  is never actually navigated to; gsi-server's test-only auth shortcut
  (`GET {authorization_endpoint}?request_uri=...&user_id=<KVNR-shaped>`, `FedIdpController.
  getAuthorizationCode`) mints a real authorization code for any `[A-Z]\\d{9}` value
  without any real authentication happening. `code`/`state` are read straight off the
  `Location` header rather than following the redirect, exactly as the docstring above
  the fixtures already does for `_authorize_and_get_code` below.
"""

from __future__ import annotations

import dataclasses
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc.jwk import ECKey

from gesundheitsid.errors import ProtocolError
from gesundheitsid.federation import TrustChain
from gesundheitsid.oidc import (
    exchange_code,
    generate_nonce,
    generate_pkce,
    generate_state,
    parse_id_token,
    push_authorization_request,
)
from gesundheitsid.oidc.par import REQUEST_URI_EXPIRY_SECONDS
from tests.integration.conftest import REDIRECT_URI, RP_ISSUER, SCOPES, TEST_USER_ID

pytestmark = pytest.mark.integration


def _authorize_and_get_code(http_client: httpx.Client, trust_chain: TrustChain, request_uri: str, state: str) -> str:
    """Drive gsi-server's test-only auth shortcut and extract `code` from the resulting
    302's `Location` header -- see this module's docstring for why nothing here follows
    a real redirect or lands on a real page."""
    auth_endpoint = trust_chain.metadata["openid_provider"]["authorization_endpoint"]
    response = http_client.get(
        auth_endpoint, params={"request_uri": request_uri, "user_id": TEST_USER_ID}, follow_redirects=False
    )
    assert response.status_code == 302, f"expected a redirect, got {response.status_code}: {response.text}"
    location = response.headers["location"]
    query = parse_qs(urlsplit(location).query)
    assert query.get("state") == [state], f"state mismatch in redirect: {location}"
    return query["code"][0]


def test_par_returns_a_request_uri_with_the_documented_ttl(mtls_client: httpx.Client, trust_chain: TrustChain) -> None:
    """gematik's wiki documents a 90-second request_uri lifetime -- assert the real
    server actually honors it, not just that PAR succeeds at all."""
    par_response = push_authorization_request(
        trust_chain=trust_chain,
        client_id=RP_ISSUER,
        redirect_uri=REDIRECT_URI,
        scopes=SCOPES,
        pkce=generate_pkce(),
        state=generate_state(),
        nonce=generate_nonce(),
        http_client=mtls_client,
    )

    assert par_response.request_uri
    assert par_response.expires_in == 90
    assert par_response.expires_in == REQUEST_URI_EXPIRY_SECONDS


def test_happy_path_par_through_identity(
    http_client: httpx.Client, mtls_client: httpx.Client, trust_chain: TrustChain, rp_idtoken_enc_key: ECKey
) -> None:
    """PAR -> auth shortcut -> token exchange -> parse_id_token, entirely against the
    real gsi-server, with every key `parse_id_token` verifies against resolved through
    the real trust chain -- never hand-built."""
    pkce = generate_pkce()
    state = generate_state()
    nonce = generate_nonce()

    par_response = push_authorization_request(
        trust_chain=trust_chain,
        client_id=RP_ISSUER,
        redirect_uri=REDIRECT_URI,
        scopes=SCOPES,
        pkce=pkce,
        state=state,
        nonce=nonce,
        http_client=mtls_client,
    )

    code = _authorize_and_get_code(http_client, trust_chain, par_response.request_uri, state)

    token_response = exchange_code(
        trust_chain=trust_chain,
        client_id=RP_ISSUER,
        redirect_uri=REDIRECT_URI,
        code=code,
        pkce=pkce,
        http_client=mtls_client,
    )
    # a JWE, not a plain JWT: 5 dot-separated segments (header.key.iv.ciphertext.tag),
    # never 3 -- see gesundheitsid/oidc/idtoken.py's module docstring.
    assert len(token_response.id_token.split(".")) == 5

    identity = parse_id_token(
        token=token_response.id_token,
        trust_chain=trust_chain,
        encryption_key=rp_idtoken_enc_key,
        client_id=RP_ISSUER,
        nonce=nonce,
    )

    assert identity.acr == "gematik-ehealth-loa-high"
    # TEST_USER_ID is gsi-server's own canned shortcut value, not a real KVNR -- see its
    # definition in conftest.py for why asserting on it is not the "never log a raw
    # KVNR" rule's concern.
    assert identity.kvnr == TEST_USER_ID
    assert identity.subject is not None


def test_par_without_client_certificate_is_rejected(
    http_client: httpx.Client, trust_chain: TrustChain, rp_is_registered: None
) -> None:
    """self_signed_tls_client_auth actually enforced: a PAR with no client certificate
    at all must fail now that GSI_CLIENT_CERT_REQUIRED is on (see docker-compose.yml).
    Uses the plain `http_client` fixture -- no cert, no key -- deliberately, in place of
    `mtls_client`."""
    with pytest.raises(ProtocolError, match="client certificate is missing"):
        push_authorization_request(
            trust_chain=trust_chain,
            client_id=RP_ISSUER,
            redirect_uri=REDIRECT_URI,
            scopes=SCOPES,
            pkce=generate_pkce(),
            state=generate_state(),
            nonce=generate_nonce(),
            http_client=http_client,
        )


def test_wrong_code_verifier_is_rejected(
    http_client: httpx.Client, mtls_client: httpx.Client, trust_chain: TrustChain
) -> None:
    """RFC 7636: the token endpoint must recompute SHA256(code_verifier) and compare it
    against the code_challenge pushed at PAR time -- a mismatched verifier must fail
    even though `code` itself is genuine and unexpired."""
    pkce = generate_pkce()
    state = generate_state()

    par_response = push_authorization_request(
        trust_chain=trust_chain,
        client_id=RP_ISSUER,
        redirect_uri=REDIRECT_URI,
        scopes=SCOPES,
        pkce=pkce,
        state=state,
        nonce=generate_nonce(),
        http_client=mtls_client,
    )
    code = _authorize_and_get_code(http_client, trust_chain, par_response.request_uri, state)

    wrong_pkce = dataclasses.replace(pkce, verifier="wrong-verifier-wrong-verifier-0123456789abcdef")

    with pytest.raises(ProtocolError, match="code_verifier"):
        exchange_code(
            trust_chain=trust_chain,
            client_id=RP_ISSUER,
            redirect_uri=REDIRECT_URI,
            code=code,
            pkce=wrong_pkce,
            http_client=mtls_client,
        )


def test_replayed_authorization_code_is_rejected(
    http_client: httpx.Client, mtls_client: httpx.Client, trust_chain: TrustChain
) -> None:
    """An authorization code is single-use by contract (RFC 6749 S4.1.2): gsi-server
    deletes the session the moment it issues tokens for it
    (`FedIdpController.getTokensForCode` -> `fedIdpAuthSessions.remove(sessionKey)`), so
    exchanging the SAME code twice must fail the second time -- a mock can only ever
    assert this project's own client sent the right request, never that a real,
    stateful counterparty actually enforced single-use."""
    pkce = generate_pkce()
    state = generate_state()
    nonce = generate_nonce()

    par_response = push_authorization_request(
        trust_chain=trust_chain,
        client_id=RP_ISSUER,
        redirect_uri=REDIRECT_URI,
        scopes=SCOPES,
        pkce=pkce,
        state=state,
        nonce=nonce,
        http_client=mtls_client,
    )
    code = _authorize_and_get_code(http_client, trust_chain, par_response.request_uri, state)

    first = exchange_code(
        trust_chain=trust_chain,
        client_id=RP_ISSUER,
        redirect_uri=REDIRECT_URI,
        code=code,
        pkce=pkce,
        http_client=mtls_client,
    )
    assert first.id_token

    with pytest.raises(ProtocolError, match="unknown code"):
        exchange_code(
            trust_chain=trust_chain,
            client_id=RP_ISSUER,
            redirect_uri=REDIRECT_URI,
            code=code,
            pkce=pkce,
            http_client=mtls_client,
        )


def test_expired_request_uri_is_rejected(
    http_client: httpx.Client, mtls_client: httpx.Client, trust_chain: TrustChain
) -> None:
    """gsi-server's own request_uri TTL is a fixed 90 seconds
    (`GsiConfiguration.requestUriTTL`, `application.yml`, not overridden -- see
    docker-compose.yml) and `test_par_returns_a_request_uri_with_the_documented_ttl`
    above asserts exactly that value, so it cannot be shortened for this test without
    contradicting that one. There is no admin/test endpoint to force-expire a session
    early, so this really does wait out the TTL -- the ~92 second real-time cost is the
    honest price of testing a real, stateful counterparty's own expiry enforcement
    rather than asserting our own client's belief about it.
    """
    par_response = push_authorization_request(
        trust_chain=trust_chain,
        client_id=RP_ISSUER,
        redirect_uri=REDIRECT_URI,
        scopes=SCOPES,
        pkce=generate_pkce(),
        state=generate_state(),
        nonce=generate_nonce(),
        http_client=mtls_client,
    )

    time.sleep(par_response.expires_in + 2)

    auth_endpoint = trust_chain.metadata["openid_provider"]["authorization_endpoint"]
    response = http_client.get(
        auth_endpoint,
        params={"request_uri": par_response.request_uri, "user_id": TEST_USER_ID},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "expired" in response.json().get("error_description", "").lower()

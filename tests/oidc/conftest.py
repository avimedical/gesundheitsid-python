"""A fake sectoral IdP for OIDC protocol-layer tests: PAR/authorization/token endpoints
wired through respx, plus a `TrustChain` built with real P-256 keys the way a relying
party would actually hold one after a successful `resolve_trust_chain` call.

Trust-chain *resolution* itself (the Federation Master round trip, subordinate-statement
verification, all its failure modes) is already exercised end-to-end in
`tests/federation/test_trust_chain.py` against the `fake_federation` fixture there. Redoing
that machinery here would only add coupling without adding coverage, so this fixture
constructs the resolved `TrustChain` directly -- real signing/encryption keys, real ES256
signatures where a test builds a token, but no second federation stood up just to arrive at
the same dataclass tests/federation already proves `resolve_trust_chain` produces.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import pytest
from joserfc.jwk import ECKey

from gesundheitsid.crypto import KeyPurpose, generate_p256_key, public_jwks
from gesundheitsid.federation.trust_chain import TrustChain

IDP_ISSUER = "https://sektoraler-idp.example.com"
FM_BASE_URL = "https://fedmaster.example.com"

PAR_ENDPOINT = f"{IDP_ISSUER}/par"
AUTHORIZATION_ENDPOINT = f"{IDP_ISSUER}/auth"
TOKEN_ENDPOINT = f"{IDP_ISSUER}/token"

CLIENT_ID = "https://fachdienst.example.com"
REDIRECT_URI = "https://fachdienst.example.com/callback"

#: how long the fake trust chain / its statements are valid for, in seconds from build time
DEFAULT_LIFETIME_SECONDS = 3600


@dataclass
class FakeIdp:
    trust_chain: TrustChain
    #: the key the subordinate statement vouches for -- what a real sectoral IdP signs its
    #: ID tokens with, per gemSpec_IDP_Sek. Deliberately distinct from any key the fixture
    #: does NOT put in trust_chain.signing_keys (see test_idtoken.py's untrusted-key case).
    signing_key: ECKey
    #: this relying party's own IDTOKEN_ENC key; the IdP encrypts ID tokens to its public half.
    enc_key: ECKey


@pytest.fixture
def fake_idp() -> FakeIdp:
    signing_key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
    enc_key = generate_p256_key(KeyPurpose.IDTOKEN_ENC)

    trust_chain = TrustChain(
        subject=IDP_ISSUER,
        trust_anchor=FM_BASE_URL,
        signing_keys=public_jwks([signing_key]),
        metadata={
            "openid_provider": {
                "issuer": IDP_ISSUER,
                "pushed_authorization_request_endpoint": PAR_ENDPOINT,
                "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                "token_endpoint": TOKEN_ENDPOINT,
            }
        },
        expires_at=int(time.time()) + DEFAULT_LIFETIME_SECONDS,
    )

    return FakeIdp(trust_chain=trust_chain, signing_key=signing_key, enc_key=enc_key)

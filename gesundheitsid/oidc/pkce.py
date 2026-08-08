"""PKCE (RFC 7636) verifier/challenge pairs, plus the `state`/`nonce` values that protect
the authorization-code flow against CSRF and ID token replay.

All three generators use `secrets`, never `random` -- `random` is a non-cryptographic PRNG
seeded from process-visible state, so its output is predictable enough that an attacker who
can observe or influence that state could pre-compute a verifier/state/nonce and hijack
someone else's authorization flow. `secrets` draws from the OS CSPRNG, which is the whole
point of these values existing at all.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass

__all__ = ["PkceMaterial", "generate_pkce", "generate_state", "generate_nonce"]

#: 32 raw bytes -> 256 bits of entropy, comfortably above RFC 7636's 128-bit minimum for a
#: code_verifier, and the same amount reused for state/nonce since both serve an equivalent
#: unguessability role.
_ENTROPY_BYTES = 32


def _b64url(data: bytes) -> str:
    """Base64url-encode `data` with padding stripped, per RFC 7636 / OAuth2's convention."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class PkceMaterial:
    """A PKCE verifier/challenge pair. `verifier` stays with the caller (never sent in the
    PAR request); `challenge` is what gets pushed to the IdP."""

    verifier: str
    challenge: str
    method: str = "S256"


def generate_pkce() -> PkceMaterial:
    """Generate a fresh S256 PKCE verifier/challenge pair.

    Per RFC 7636 Section 4.2, the challenge is BASE64URL(SHA256(ASCII(verifier))) -- the
    hash input is the verifier's own base64url *text*, not the raw entropy bytes behind it.
    """
    verifier = _b64url(secrets.token_bytes(_ENTROPY_BYTES))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return PkceMaterial(verifier=verifier, challenge=challenge)


def generate_state() -> str:
    """A fresh, unguessable `state` value for CSRF protection on the authorization request."""
    return _b64url(secrets.token_bytes(_ENTROPY_BYTES))


def generate_nonce() -> str:
    """A fresh, unguessable `nonce` value to bind the authorization request to its ID token."""
    return _b64url(secrets.token_bytes(_ENTROPY_BYTES))

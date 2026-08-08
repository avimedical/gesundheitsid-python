"""Sectoral IdP ID token decryption, signature verification, claim validation, and identity
extraction.

CAVEAT: the `urn:telematik:claims:*` URNs below are drawn from gematik's public wiki and
other secondary sources, not cross-checked line-by-line against the current normative
`gemSpec_IDP_Sek`. Confirm the exact claim URNs (and whether the IdP sends any others worth
surfacing) against that spec before depending on this list for anything beyond a first
integration. The processing *order* below (decrypt, then verify, then validate, then check
`acr`) is not affected by that uncertainty -- it follows directly from what a JWE-wrapping-
a-JWS structurally allows you to know at each step.
"""

from __future__ import annotations

from dataclasses import dataclass

from joserfc.jwk import ECKey

from gesundheitsid.crypto import decrypt_id_token, load_jwks, validate_claims, verify_compact
from gesundheitsid.errors import CryptoError, ProtocolError
from gesundheitsid.federation.trust_chain import TrustChain

__all__ = ["GesundheitsIdIdentity", "REQUIRED_ACR", "parse_id_token"]

#: the only acr value gemSpec_IDP_Sek documents for a successfully authenticated insured
#: person. Anything else is not a "weaker" identity to hand back to the caller -- it is a
#: login this library refuses to turn into an identity at all.
REQUIRED_ACR = "gematik-ehealth-loa-high"

# Indicative only -- see the module docstring's caveat.
_CLAIM_KVNR = "urn:telematik:claims:id"
_CLAIM_ORGANIZATION = "urn:telematik:claims:organization"
_CLAIM_DISPLAY_NAME = "urn:telematik:claims:display_name"
_CLAIM_PROFESSION = "urn:telematik:claims:profession"


@dataclass(frozen=True)
class GesundheitsIdIdentity:
    """The insured person's identity, extracted from a decrypted, verified, validated ID
    token.

    Only `acr` is guaranteed non-None -- `parse_id_token` enforces it before this object
    is ever built. Every other convenience field is None when its claim was simply absent
    from the token, never raised on: the exact claim set a given sectoral IdP sends is not
    something this library can fully pin down (see module docstring), so an unfamiliar or
    missing optional claim must degrade gracefully rather than break the whole login.
    `claims` is the complete, verified raw payload for anything not surfaced by name here.
    """

    kvnr: str | None
    display_name: str | None
    insurer_id: str | None
    profession: str | None
    acr: str
    amr: list[str] | None
    subject: str | None
    email: str | None
    claims: dict


def parse_id_token(
    *,
    token: str,
    trust_chain: TrustChain,
    encryption_key: ECKey,
    client_id: str,
    nonce: str,
    now: int | None = None,
) -> GesundheitsIdIdentity:
    """Decrypt, verify, and validate a sectoral IdP ID token; extract a `GesundheitsIdIdentity`.

    Order is deliberate and matters:
      1. Decrypt the outer JWE with our own `encryption_key`. This proves only that we
         were the intended recipient of the ciphertext -- nothing about who signed the
         plaintext inside it (see `crypto.jose`'s module docstring).
      2. Verify the inner JWS's signature against `trust_chain.signing_keys` -- the
         Federation Master's subordinate statement about the IdP, never any key the IdP
         might present out of band. Using anything else here would let a compromised or
         merely misconfigured IdP endpoint smuggle in its own signing key.
      3. Validate `iss`/`aud`/`nonce`/`exp`, requiring both `exp` and `acr` to be present.
      4. Assert `acr == gematik-ehealth-loa-high`. A token that decrypts and verifies
         cleanly but was issued at a lower assurance level must never produce an
         identity -- there is no reduced-trust fallback.
      5. Only once all of the above holds, extract the convenience fields.
    """
    try:
        inner_jws = decrypt_id_token(token, encryption_key)
    except CryptoError as exc:
        raise ProtocolError(f"id_token could not be decrypted: {exc}") from exc

    signing_keys = load_jwks(trust_chain.signing_keys)
    try:
        claims = verify_compact(inner_jws, signing_keys)
    except CryptoError as exc:
        raise ProtocolError(f"id_token signature verification failed: {exc}") from exc

    try:
        validate_claims(
            claims,
            issuer=trust_chain.subject,
            audience=client_id,
            nonce=nonce,
            now=now,
            required=("exp", "acr"),
        )
    except CryptoError as exc:
        raise ProtocolError(f"id_token failed claim validation: {exc}") from exc

    acr = claims.get("acr")
    if acr != REQUIRED_ACR:
        raise ProtocolError(f"id_token acr is {acr!r}, expected {REQUIRED_ACR!r} -- refusing to build an identity")

    return GesundheitsIdIdentity(
        kvnr=claims.get(_CLAIM_KVNR),
        display_name=claims.get(_CLAIM_DISPLAY_NAME),
        insurer_id=claims.get(_CLAIM_ORGANIZATION),
        profession=claims.get(_CLAIM_PROFESSION),
        acr=acr,
        amr=claims.get("amr"),
        subject=claims.get("sub"),
        email=claims.get("email"),
        claims=claims,
    )

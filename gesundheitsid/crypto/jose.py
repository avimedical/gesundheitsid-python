"""JOSE operations for GesundheitsID: ES256 signing, the sectoral IdP's ECDH-ES/A256GCM
ID token envelope, and claim validation.

A sectoral IdP's ID token is a JWE wrapping a JWS, not a plain JWT: decrypt first, then
verify the inner JWS as a separate step. A successful decrypt only proves
confidentiality of the ciphertext, never who signed the payload inside it.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable

from joserfc import jwe, jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey, KeySet
from joserfc.util import to_bytes, urlsafe_b64decode

from gesundheitsid.errors import CryptoError

__all__ = [
    "sign_compact",
    "verify_compact",
    "encrypt_id_token",
    "decrypt_id_token",
    "unverified_header",
    "unverified_claims",
    "validate_claims",
]

#: the only signature algorithm this library ever produces or accepts
_SIG_ALGORITHMS = ["ES256"]
#: the only key-management/content-encryption pair the sectoral IdP envelope uses
_ENC_ALG = "ECDH-ES"
_ENC_ENC = "A256GCM"


def sign_compact(payload: dict, key: ECKey, typ: str = "JWT") -> str:
    """Sign `payload` as a compact ES256 JWS. `key` must already carry a `kid`."""
    if key.kid is None:
        raise CryptoError("signing key has no 'kid'; set one before signing")

    header = {"alg": "ES256", "typ": typ, "kid": key.kid}
    body = json.dumps(payload).encode("utf-8")
    try:
        return jws.serialize_compact(header, body, key, algorithms=_SIG_ALGORITHMS)
    except JoseError as exc:
        raise CryptoError(f"failed to sign token: {exc}") from exc


def verify_compact(token: str, keys: KeySet | ECKey) -> dict:
    """Verify a compact JWS and return its claims.

    Algorithms are pinned to ES256 explicitly (never inferred from the token's own
    header, and never `none`) -- accepting whatever the header claims would let an
    attacker choose their own verification algorithm.
    """
    try:
        obj = jws.deserialize_compact(token, keys, algorithms=_SIG_ALGORITHMS)
    except JoseError as exc:
        raise CryptoError(f"signature verification failed: {exc}") from exc

    try:
        return json.loads(obj.payload)
    except (TypeError, ValueError) as exc:
        raise CryptoError(f"token payload is not valid JSON: {exc}") from exc


def encrypt_id_token(inner_jws: str, recipient_public_key: ECKey) -> str:
    """Wrap an inner ES256 JWS as an ECDH-ES/A256GCM JWE.

    Mainly useful for producing realistic fixtures in tests -- this is exactly what a
    sectoral IdP sends -- but kept as public API since any consumer testing their own
    integration needs the same capability.
    """
    header = {"alg": _ENC_ALG, "enc": _ENC_ENC}
    try:
        return jwe.encrypt_compact(header, inner_jws, recipient_public_key, algorithms=[_ENC_ALG, _ENC_ENC])
    except JoseError as exc:
        raise CryptoError(f"failed to encrypt id token: {exc}") from exc


def decrypt_id_token(jwe_token: str, enc_private_key: ECKey) -> str:
    """Decrypt a sectoral IdP ID token JWE and return the inner JWS compact string.

    The returned string is only decrypted, not verified -- callers must still run it
    through `verify_compact` before trusting any claim inside it.
    """
    try:
        obj = jwe.decrypt_compact(jwe_token, enc_private_key, algorithms=[_ENC_ALG, _ENC_ENC])
    except JoseError as exc:
        raise CryptoError(f"failed to decrypt id token: {exc}") from exc

    if obj.plaintext is None:
        raise CryptoError("decrypted id token has no plaintext")
    return obj.plaintext.decode("utf-8")


def unverified_header(token: str) -> dict:
    """Decode a compact JOSE token's header WITHOUT verifying its signature/encryption.

    Only for reading `kid`/`alg` to select which key to verify or decrypt with next --
    the returned dict is attacker-controlled and must never be treated as trustworthy.
    """
    try:
        segment = to_bytes(token).split(b".", 1)[0]
        return json.loads(urlsafe_b64decode(segment))
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"could not decode token header: {exc}") from exc


def unverified_claims(token: str) -> dict:
    """Decode a compact JWS's claims WITHOUT verifying its signature.

    Only meaningful for a JWS (3 segments): a JWE's second segment is an encrypted key,
    not JSON. Used to read `iss`/`sub` before you know which key verifies the token --
    never treat the result as authenticated.
    """
    parts = to_bytes(token).split(b".")
    if len(parts) != 3:
        raise CryptoError("not a compact JWS (expected exactly 3 dot-separated segments)")
    try:
        return json.loads(urlsafe_b64decode(parts[1]))
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"could not decode token claims: {exc}") from exc


def validate_claims(
    claims: dict,
    *,
    issuer: str | None = None,
    audience: str | Iterable[str] | None = None,
    nonce: str | None = None,
    now: int | None = None,
    leeway: int = 30,
    required: Iterable[str] = ("exp",),
) -> None:
    """Validate standard JWT timing/identity claims.

    Raises CryptoError with a message naming the specific failing claim (`exp`, `nbf`,
    `iat`, `iss`, `aud`, or `nonce`) rather than one generic "invalid token" message,
    so callers and logs can tell which check actually failed.

    `required` defaults to `("exp",)` and fails closed: every other check below is a
    no-op when its claim is absent, so without this a token carrying no `exp` at all
    would validate happily and then never expire. Both entity statements and sectoral
    IdP ID tokens must carry `exp`, so absence is a defect, not a permissive case.
    """
    current = now if now is not None else int(time.time())

    for name in required:
        if claims.get(name) is None:
            raise CryptoError(f"{name}: required claim is missing")

    exp = claims.get("exp")
    if exp is not None and current > exp + leeway:
        raise CryptoError("exp: token has expired")

    nbf = claims.get("nbf")
    if nbf is not None and current < nbf - leeway:
        raise CryptoError("nbf: token is not yet valid")

    iat = claims.get("iat")
    if iat is not None and iat > current + leeway:
        raise CryptoError("iat: token was issued in the future")

    if issuer is not None and claims.get("iss") != issuer:
        raise CryptoError(f"iss: expected '{issuer}', got '{claims.get('iss')}'")

    if audience is not None:
        claim_aud = claims.get("aud")
        expected = {audience} if isinstance(audience, str) else set(audience)
        actual = {claim_aud} if isinstance(claim_aud, str) else set(claim_aud or [])
        if not expected & actual:
            raise CryptoError(f"aud: expected one of {sorted(expected)}, got '{claim_aud}'")

    if nonce is not None and claims.get("nonce") != nonce:
        raise CryptoError(f"nonce: expected '{nonce}', got '{claims.get('nonce')}'")

"""sign/verify (ES256), the sectoral IdP JWE(ECDH-ES,A256GCM)->JWS(ES256) envelope, and
claim validation -- one negative test per distinct failure mode.
"""

import time

import pytest
from joserfc import jws as raw_jws
from joserfc.jwk import ECKey

from gesundheitsid.crypto.jose import (
    decrypt_id_token,
    encrypt_id_token,
    sign_compact,
    unverified_claims,
    unverified_header,
    validate_claims,
    verify_compact,
)
from gesundheitsid.crypto.keys import KeyPurpose, generate_p256_key
from gesundheitsid.errors import CryptoError


def _claims(**overrides: object) -> dict:
    now = int(time.time())
    base = {
        "iss": "https://idp.example.com",
        "aud": "https://rp.example.com",
        "sub": "user-1",
        "nonce": "the-nonce",
        "iat": now,
        "exp": now + 300,
    }
    base.update(overrides)
    return base


def _envelope(claims: dict) -> tuple[str, ECKey, ECKey]:
    """Sign `claims` and wrap them as the sectoral IdP would; returns (jwe, sig_key, enc_key)."""
    sig_key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
    enc_key = generate_p256_key(KeyPurpose.IDTOKEN_ENC)
    inner = sign_compact(claims, sig_key)
    envelope = encrypt_id_token(inner, enc_key)
    return envelope, sig_key, enc_key


def test_full_round_trip_sign_encrypt_decrypt_verify() -> None:
    claims = _claims()
    envelope, sig_key, enc_key = _envelope(claims)

    inner = decrypt_id_token(envelope, enc_key)
    recovered = verify_compact(inner, sig_key)

    assert recovered == claims
    validate_claims(recovered, issuer=claims["iss"], audience=claims["aud"], nonce=claims["nonce"])


def test_sign_compact_sets_alg_typ_and_kid_header() -> None:
    key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    token = sign_compact({"a": 1}, key, typ="entity-statement+jwt")

    header = unverified_header(token)
    assert header == {"alg": "ES256", "typ": "entity-statement+jwt", "kid": key.kid}


def test_verify_compact_accepts_a_key_set() -> None:
    from joserfc.jwk import KeySet

    key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
    token = sign_compact({"hello": "world"}, key)

    claims = verify_compact(token, KeySet([key]))
    assert claims == {"hello": "world"}


def test_verify_compact_rejects_a_tampered_signature() -> None:
    key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
    token = sign_compact({"hello": "world"}, key)
    header, payload, signature = token.split(".")
    flipped_char = "A" if signature[-1] != "A" else "B"
    tampered = f"{header}.{payload}.{signature[:-1]}{flipped_char}"

    with pytest.raises(CryptoError):
        verify_compact(tampered, key)


def test_verify_compact_rejects_an_algorithm_other_than_es256() -> None:
    p384_key = ECKey.generate_key(crv="P-384", private=True)
    token = raw_jws.serialize_compact({"alg": "ES384", "typ": "JWT"}, b"{}", p384_key, algorithms=["ES384"])

    with pytest.raises(CryptoError):
        verify_compact(token, p384_key)


def test_validate_claims_rejects_a_token_with_no_exp() -> None:
    """A token with no `exp` never expires, so absence must fail rather than pass silently.

    Every other check in validate_claims is a no-op when its claim is absent, which makes
    this the one place the function could otherwise fail open.
    """
    claims = _claims()
    del claims["exp"]

    with pytest.raises(CryptoError, match="exp"):
        validate_claims(claims)


def test_validate_claims_can_require_additional_claims() -> None:
    """A sectoral IdP ID token must carry `acr`; callers express that via `required`."""
    claims = _claims()  # carries no 'acr'

    with pytest.raises(CryptoError, match="acr"):
        validate_claims(claims, required=("exp", "acr"))

    validate_claims(_claims(acr="gematik-ehealth-loa-high"), required=("exp", "acr"))


def test_validate_claims_rejects_wrong_audience() -> None:
    claims = _claims()
    with pytest.raises(CryptoError, match="aud"):
        validate_claims(claims, audience="https://someone-else.example.com")


def test_validate_claims_accepts_audience_as_a_list_member() -> None:
    claims = _claims(aud=["https://rp.example.com", "https://other.example.com"])
    validate_claims(claims, audience="https://rp.example.com")  # must not raise


def test_validate_claims_rejects_wrong_nonce() -> None:
    claims = _claims()
    with pytest.raises(CryptoError, match="nonce"):
        validate_claims(claims, nonce="not-the-nonce")


def test_validate_claims_rejects_an_expired_token() -> None:
    claims = _claims(exp=int(time.time()) - 1000)
    with pytest.raises(CryptoError, match="exp"):
        validate_claims(claims, leeway=0)


def test_validate_claims_rejects_nbf_in_the_future() -> None:
    claims = _claims(nbf=int(time.time()) + 1000)
    with pytest.raises(CryptoError, match="nbf"):
        validate_claims(claims, leeway=0)


def test_validate_claims_rejects_wrong_issuer() -> None:
    claims = _claims()
    with pytest.raises(CryptoError, match="iss"):
        validate_claims(claims, issuer="https://not-the-idp.example.com")


def test_decrypt_id_token_rejects_the_wrong_key() -> None:
    envelope, _sig_key, _enc_key = _envelope(_claims())
    wrong_key = generate_p256_key(KeyPurpose.IDTOKEN_ENC)

    with pytest.raises(CryptoError):
        decrypt_id_token(envelope, wrong_key)


def test_unverified_header_and_claims_read_without_verifying() -> None:
    key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
    token = sign_compact({"sub": "user-1"}, key)

    assert unverified_header(token)["kid"] == key.kid
    assert unverified_claims(token) == {"sub": "user-1"}


def test_unverified_claims_rejects_a_non_compact_jws() -> None:
    with pytest.raises(CryptoError):
        unverified_claims("not-a-jws")

"""generate_p256_key, JWKS rendering, self-signed certs, and the P-256-only guard."""

import base64

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from joserfc import jwk as joserfc_jwk
from joserfc.jwk import ECKey

from gesundheitsid.crypto.keys import (
    KeyPurpose,
    assert_p256,
    attach_x5c,
    generate_p256_key,
    generate_self_signed_cert,
    load_jwks,
    private_jwks,
    public_jwks,
)
from gesundheitsid.errors import CryptoError


def _thumbprint_of(key: ECKey) -> str:
    """Recompute the RFC 7638 thumbprint independently, from the public members only."""
    return joserfc_jwk.thumbprint({"kty": "EC", "crv": key["crv"], "x": key["x"], "y": key["y"]})


@pytest.mark.parametrize("purpose", list(KeyPurpose))
def test_generate_p256_key_sets_kid_use_and_alg(purpose: KeyPurpose) -> None:
    key = generate_p256_key(purpose)

    assert key.curve_name == "P-256"
    assert key.kid == _thumbprint_of(key)
    if purpose is KeyPurpose.IDTOKEN_ENC:
        assert key.get("use") == "enc"
        assert key.get("alg") == "ECDH-ES"
    else:
        assert key.get("use") == "sig"
        assert key.get("alg") == "ES256"


def test_generate_p256_key_honors_an_explicit_kid() -> None:
    key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG, kid="my-fixed-kid")
    assert key.kid == "my-fixed-kid"


def test_public_jwks_never_leaks_private_material() -> None:
    keys = [generate_p256_key(p) for p in KeyPurpose]
    doc = public_jwks(keys)

    assert set(doc.keys()) == {"keys"}
    assert len(doc["keys"]) == len(keys)
    for entry in doc["keys"]:
        assert "d" not in entry, "public JWKS entry must never carry the private 'd' member"


def test_private_jwks_includes_d_and_round_trips_through_load_jwks() -> None:
    keys = [generate_p256_key(p) for p in KeyPurpose]
    doc = private_jwks(keys)

    for entry in doc["keys"]:
        assert "d" in entry

    key_set = load_jwks(doc)
    assert len(key_set.keys) == len(keys)

    # load_jwks also accepts the document as a JSON string, not just a dict
    import json

    key_set_from_text = load_jwks(json.dumps(doc))
    assert len(key_set_from_text.keys) == len(keys)


def test_private_jwks_rejects_a_public_only_key() -> None:
    private_key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
    public_only = ECKey.import_key(private_key.as_dict(private=False))

    with pytest.raises(CryptoError):
        private_jwks([public_only])


def test_self_signed_cert_round_trips_and_x5c_uses_standard_base64() -> None:
    key = generate_p256_key(KeyPurpose.MTLS_CLIENT)
    cert = generate_self_signed_cert(key, subject_cn="rp.example.com", valid_days=30)

    assert cert.subject.rfc4514_string() == "CN=rp.example.com"
    assert cert.issuer == cert.subject  # self-signed

    keyed = attach_x5c(key, cert)
    x5c_entries = keyed.as_dict(private=False)["x5c"]
    assert len(x5c_entries) == 1

    # RFC 7517 x5c is *standard* base64 (RFC 4648 Section 4) -- not base64url. Decoding
    # it with the standard alphabet must reproduce the certificate's raw DER bytes.
    decoded_der = base64.b64decode(x5c_entries[0], validate=True)
    assert decoded_der == cert.public_bytes(Encoding.DER)


def test_assert_p256_accepts_p256() -> None:
    assert_p256(generate_p256_key(KeyPurpose.DOWNSTREAM_SIG))  # must not raise


def test_assert_p256_rejects_a_p384_key() -> None:
    p384_key = ECKey.generate_key(crv="P-384", private=True)
    with pytest.raises(CryptoError, match="P-256"):
        assert_p256(p384_key)


def test_assert_p256_rejects_a_non_ec_key() -> None:
    from joserfc.jwk import OctKey

    with pytest.raises(CryptoError):
        assert_p256(OctKey.generate_key(256))

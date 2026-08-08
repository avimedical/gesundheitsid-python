"""parse_id_token: decrypt -> verify-against-trust-chain -> validate -> acr gate -> extract.

One negative test per distinct failure mode, mirroring tests/crypto/test_jose.py's style.
"""

from __future__ import annotations

import time

import pytest
from joserfc.jwk import ECKey

from gesundheitsid.crypto import KeyPurpose, encrypt_id_token, generate_p256_key, sign_compact
from gesundheitsid.errors import ProtocolError
from gesundheitsid.oidc.idtoken import REQUIRED_ACR, parse_id_token
from tests.oidc.conftest import CLIENT_ID, FakeIdp

_NONCE = "the-nonce"


def _claims(**overrides: object) -> dict:
    now = int(time.time())
    base = {
        "iss": "https://sektoraler-idp.example.com",  # == conftest.IDP_ISSUER
        "aud": CLIENT_ID,
        "sub": "the-subject",
        "nonce": _NONCE,
        "iat": now,
        "exp": now + 300,
        "acr": REQUIRED_ACR,
        "urn:telematik:claims:id": "X123456789",
        "urn:telematik:claims:organization": "104212059",
        "urn:telematik:claims:display_name": "Erika Mustermann",
        "urn:telematik:claims:profession": "1.2.276.0.76.4.49",
        "email": "erika@example.com",
    }
    base.update(overrides)
    return base


def _envelope(claims: dict, *, signing_key: ECKey, enc_key: ECKey) -> str:
    inner = sign_compact(claims, signing_key)
    return encrypt_id_token(inner, enc_key)


def _parse(token: str, fake_idp: FakeIdp, **overrides: object):
    kwargs: dict[str, object] = {
        "token": token,
        "trust_chain": fake_idp.trust_chain,
        "encryption_key": fake_idp.enc_key,
        "client_id": CLIENT_ID,
        "nonce": _NONCE,
    }
    kwargs.update(overrides)
    return parse_id_token(**kwargs)  # type: ignore[arg-type]


def test_full_round_trip_extracts_kvnr_and_insurer(fake_idp: FakeIdp) -> None:
    token = _envelope(_claims(), signing_key=fake_idp.signing_key, enc_key=fake_idp.enc_key)

    identity = _parse(token, fake_idp)

    assert identity.kvnr == "X123456789"
    assert identity.insurer_id == "104212059"
    assert identity.display_name == "Erika Mustermann"
    assert identity.profession == "1.2.276.0.76.4.49"
    assert identity.acr == REQUIRED_ACR
    assert identity.subject == "the-subject"
    assert identity.email == "erika@example.com"
    assert identity.claims["urn:telematik:claims:id"] == "X123456789"


def test_absent_optional_claims_produce_an_identity_with_none_fields(fake_idp: FakeIdp) -> None:
    claims = _claims()
    del claims["email"]
    del claims["urn:telematik:claims:display_name"]
    token = _envelope(claims, signing_key=fake_idp.signing_key, enc_key=fake_idp.enc_key)

    identity = _parse(token, fake_idp)

    assert identity.email is None
    assert identity.display_name is None
    # the claims that ARE present must still come through -- absence must not be contagious
    assert identity.kvnr == "X123456789"


def test_wrong_nonce_is_rejected(fake_idp: FakeIdp) -> None:
    token = _envelope(_claims(), signing_key=fake_idp.signing_key, enc_key=fake_idp.enc_key)

    with pytest.raises(ProtocolError, match="nonce"):
        _parse(token, fake_idp, nonce="not-the-nonce")


def test_wrong_audience_is_rejected(fake_idp: FakeIdp) -> None:
    token = _envelope(_claims(), signing_key=fake_idp.signing_key, enc_key=fake_idp.enc_key)

    with pytest.raises(ProtocolError, match="aud"):
        _parse(token, fake_idp, client_id="https://someone-else.example.com")


def test_expired_id_token_is_rejected(fake_idp: FakeIdp) -> None:
    claims = _claims(exp=int(time.time()) - 1000)
    token = _envelope(claims, signing_key=fake_idp.signing_key, enc_key=fake_idp.enc_key)

    with pytest.raises(ProtocolError, match="exp"):
        _parse(token, fake_idp)


def test_acr_below_the_required_assurance_level_is_rejected(fake_idp: FakeIdp) -> None:
    claims = _claims(acr="gematik-ehealth-loa-substantial")
    token = _envelope(claims, signing_key=fake_idp.signing_key, enc_key=fake_idp.enc_key)

    with pytest.raises(ProtocolError, match="acr"):
        _parse(token, fake_idp)


def test_missing_acr_is_rejected(fake_idp: FakeIdp) -> None:
    claims = _claims()
    del claims["acr"]
    token = _envelope(claims, signing_key=fake_idp.signing_key, enc_key=fake_idp.enc_key)

    with pytest.raises(ProtocolError, match="acr"):
        _parse(token, fake_idp)


def test_signed_by_a_key_not_in_the_trust_chain_is_rejected(fake_idp: FakeIdp) -> None:
    # a key the trust chain never vouched for -- e.g. an attacker's, or a stale key from
    # before rotation. trust_chain.signing_keys only ever contains fake_idp.signing_key.
    untrusted_key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
    token = _envelope(_claims(), signing_key=untrusted_key, enc_key=fake_idp.enc_key)

    with pytest.raises(ProtocolError, match="signature"):
        _parse(token, fake_idp)


def test_encrypted_to_the_wrong_key_is_rejected(fake_idp: FakeIdp) -> None:
    wrong_enc_key = generate_p256_key(KeyPurpose.IDTOKEN_ENC)
    token = _envelope(_claims(), signing_key=fake_idp.signing_key, enc_key=wrong_enc_key)

    with pytest.raises(ProtocolError, match="decrypted"):
        _parse(token, fake_idp)

"""build_entity_statement's produced metadata, and parse/verify/verify_self_signed's
distinct trust levels -- unverified vs. self-signed vs. verified-against-given-keys."""

import time

import pytest
from joserfc.jwk import KeySet

from gesundheitsid.crypto import (
    KeyPurpose,
    attach_x5c,
    generate_p256_key,
    generate_self_signed_cert,
    public_jwks,
    sign_compact,
)
from gesundheitsid.errors import EntityStatementError
from gesundheitsid.federation.entity_statement import (
    build_entity_statement,
    parse_entity_statement,
    verify_entity_statement,
    verify_self_signed,
)

ISSUER = "https://gesundheitsid.example.com"
FEDERATION_MASTER = "https://app-test.federationmaster.de"


def _mtls_key() -> object:
    key = generate_p256_key(KeyPurpose.MTLS_CLIENT)
    cert = generate_self_signed_cert(key, subject_cn="gesundheitsid.example.com", valid_days=30)
    return attach_x5c(key, cert)


def _build_token(**overrides: object) -> str:
    kwargs = {
        "issuer": ISSUER,
        "signing_key": generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG),
        "federation_master": FEDERATION_MASTER,
        "redirect_uris": ["https://gesundheitsid.example.com/auth/callback"],
        "scopes": ["openid", "urn:telematik:display_name", "urn:telematik:versicherter"],
        "client_name": "GesundheitsID Example",
        "contacts": ["support@example.com"],
        "organization_name": "Example GmbH",
        "mtls_client_key": _mtls_key(),
        "idtoken_enc_key": generate_p256_key(KeyPurpose.IDTOKEN_ENC),
    }
    kwargs.update(overrides)
    return build_entity_statement(**kwargs)


def test_build_entity_statement_round_trips_through_verify_self_signed() -> None:
    now = int(time.time())
    token = _build_token(now=now, lifetime_seconds=100)

    statement = verify_self_signed(token)

    assert statement.iss == ISSUER
    assert statement.sub == ISSUER
    assert statement.iat == now
    assert statement.exp == now + 100
    assert statement.authority_hints == [FEDERATION_MASTER]


def test_build_entity_statement_sets_the_required_relying_party_metadata_fields() -> None:
    token = _build_token()
    statement = verify_self_signed(token)

    rp_metadata = statement.relying_party_metadata
    assert rp_metadata is not None
    assert rp_metadata["client_name"] == "GesundheitsID Example"
    assert rp_metadata["redirect_uris"] == ["https://gesundheitsid.example.com/auth/callback"]
    assert rp_metadata["response_types"] == ["code"]
    assert rp_metadata["grant_types"] == ["authorization_code"]
    assert rp_metadata["scope"] == "openid urn:telematik:display_name urn:telematik:versicherter"
    assert rp_metadata["client_registration_types"] == ["automatic"]
    assert rp_metadata["token_endpoint_auth_method"] == "self_signed_tls_client_auth"
    assert rp_metadata["default_acr_values"] == ["gematik-ehealth-loa-high"]
    assert rp_metadata["id_token_signed_response_alg"] == "ES256"
    assert rp_metadata["id_token_encrypted_response_alg"] == "ECDH-ES"
    assert rp_metadata["id_token_encrypted_response_enc"] == "A256GCM"


def test_build_entity_statement_metadata_jwks_holds_the_mtls_and_enc_keys() -> None:
    token = _build_token()
    statement = verify_self_signed(token)

    rp_jwks_keys = statement.relying_party_metadata["jwks"]["keys"]
    assert len(rp_jwks_keys) == 2

    sig_entries = [k for k in rp_jwks_keys if k["use"] == "sig"]
    enc_entries = [k for k in rp_jwks_keys if k["use"] == "enc"]
    assert len(sig_entries) == 1
    assert len(enc_entries) == 1
    assert "x5c" in sig_entries[0]
    assert "d" not in sig_entries[0]  # published metadata must never carry private key material
    assert "d" not in enc_entries[0]


def test_build_entity_statement_top_level_metadata_has_federation_entity_org_and_contacts() -> None:
    token = _build_token()
    statement = verify_self_signed(token)

    assert statement.metadata["federation_entity"] == {
        "organization_name": "Example GmbH",
        "contacts": ["support@example.com"],
    }
    assert statement.openid_provider_metadata is None


def test_build_entity_statement_rejects_an_mtls_key_without_x5c() -> None:
    with pytest.raises(EntityStatementError, match="x5c"):
        _build_token(mtls_client_key=generate_p256_key(KeyPurpose.MTLS_CLIENT))


def test_parse_entity_statement_does_not_verify_the_signature() -> None:
    token = _build_token()
    header, payload, _signature = token.split(".")
    tampered = f"{header}.{payload}.not-a-real-signature"

    # parse_entity_statement must not raise on a bad signature -- it never checks it.
    statement = parse_entity_statement(tampered)
    assert statement.iss == ISSUER


def test_verify_entity_statement_rejects_a_tampered_token() -> None:
    token = _build_token()
    header, payload, signature = token.split(".")
    flipped = "A" if signature[-1] != "A" else "B"
    tampered = f"{header}.{payload}.{signature[:-1]}{flipped}"

    with pytest.raises(EntityStatementError):
        verify_entity_statement(tampered, KeySet([generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)]))


def test_verify_self_signed_rejects_a_statement_signed_by_a_different_key_than_it_publishes() -> None:
    published_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    actual_signing_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    claims = {
        "iss": ISSUER,
        "sub": ISSUER,
        "iat": int(time.time()),
        "exp": int(time.time()) + 100,
        "jwks": public_jwks([published_key]),  # publishes one key...
        "authority_hints": [FEDERATION_MASTER],
        "metadata": {},
    }
    token = sign_compact(claims, actual_signing_key)  # ...but is signed by another

    with pytest.raises(EntityStatementError):
        verify_self_signed(token)


def test_verify_self_signed_rejects_a_statement_missing_required_claims() -> None:
    incomplete_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    token = sign_compact({"iss": ISSUER}, incomplete_key)

    with pytest.raises(EntityStatementError):
        verify_self_signed(token)

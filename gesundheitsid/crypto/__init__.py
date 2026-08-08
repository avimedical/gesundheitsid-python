"""Cryptographic primitives for GesundheitsID: P-256 keys, JOSE, and mTLS.

Re-exports only the deliberate public surface -- internal helpers stay import-only from
their defining module (`gesundheitsid.crypto.keys`, `.jose`, `.mtls`).
"""

from gesundheitsid.crypto.jose import (
    decrypt_id_token,
    encrypt_id_token,
    sign_compact,
    unverified_claims,
    unverified_header,
    validate_claims,
    verify_compact,
)
from gesundheitsid.crypto.keys import (
    MAX_KEY_LIFETIME_DAYS,
    KeyPurpose,
    assert_p256,
    attach_x5c,
    generate_p256_key,
    generate_self_signed_cert,
    load_jwks,
    private_jwks,
    public_jwks,
)
from gesundheitsid.crypto.mtls import (
    build_mtls_context,
    materialize_keypair,
    mtls_client,
    plain_client,
)

__all__ = [
    "MAX_KEY_LIFETIME_DAYS",
    "KeyPurpose",
    "assert_p256",
    "attach_x5c",
    "build_mtls_context",
    "decrypt_id_token",
    "encrypt_id_token",
    "generate_p256_key",
    "generate_self_signed_cert",
    "load_jwks",
    "materialize_keypair",
    "mtls_client",
    "plain_client",
    "private_jwks",
    "public_jwks",
    "sign_compact",
    "unverified_claims",
    "unverified_header",
    "validate_claims",
    "verify_compact",
]

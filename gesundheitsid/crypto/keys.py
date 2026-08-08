"""P-256 JWK lifecycle: generation, self-signed mTLS certs, and JWKS (de)serialization.

Every key in this system is P-256 -- gemSpec_IDP_Sek / gemSpec_IDP_FD do not permit any
other curve, so `assert_p256` is the gate every untrusted key (federation JWKS, a
sectoral IdP's response) must pass before use, not just something checked at generation.
"""

from __future__ import annotations

import base64
import datetime
import json
from collections.abc import Iterable
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from joserfc.jwk import ECKey, KeySet

from gesundheitsid.errors import CryptoError

__all__ = [
    "MAX_KEY_LIFETIME_DAYS",
    "KeyPurpose",
    "generate_p256_key",
    "generate_self_signed_cert",
    "attach_x5c",
    "public_jwks",
    "private_jwks",
    "load_jwks",
    "assert_p256",
]

#: gemSpec_IDP_Sek caps key validity at 398 days; rotate before this elapses.
MAX_KEY_LIFETIME_DAYS = 398

_P256 = "P-256"


class KeyPurpose(StrEnum):
    """The four P-256 keypairs a relying party needs; see the CLI's `keygen` command."""

    ENTITY_STATEMENT_SIG = "entity_statement_sig"
    MTLS_CLIENT = "mtls_client"
    IDTOKEN_ENC = "idtoken_enc"
    DOWNSTREAM_SIG = "downstream_sig"


#: purposes whose keys are used for encryption rather than signing
_ENC_PURPOSES = frozenset({KeyPurpose.IDTOKEN_ENC})


def assert_p256(key: object) -> None:
    """Raise CryptoError unless `key` is an EC JWK on the P-256 curve."""
    if not isinstance(key, ECKey):
        raise CryptoError(f"expected an EC key, got {type(key).__name__}")
    if key.curve_name != _P256:
        raise CryptoError(f"expected curve {_P256}, got {key.curve_name}")


def generate_p256_key(purpose: KeyPurpose, kid: str | None = None) -> ECKey:
    """Generate a fresh P-256 keypair for `purpose`, tagging it with `use`/`alg`/`kid`.

    `kid` defaults to the RFC 7638 JWK thumbprint so it is reproducible from the public
    parameters alone -- handy when rotating keys and needing to tell them apart without
    a side channel.
    """
    raw_key = ECKey.generate_key(crv=_P256, private=True)
    resolved_kid = kid if kid is not None else raw_key.thumbprint()

    is_enc = purpose in _ENC_PURPOSES
    data = raw_key.as_dict(private=True)
    data.update(
        {
            "kid": resolved_kid,
            "use": "enc" if is_enc else "sig",
            "alg": "ECDH-ES" if is_enc else "ES256",
        }
    )
    return ECKey.import_key(data)


def generate_self_signed_cert(
    key: ECKey,
    subject_cn: str,
    valid_days: int = MAX_KEY_LIFETIME_DAYS,
) -> x509.Certificate:
    """Self-sign `key` for `subject_cn`.

    Self-signed is correct here, not a shortcut: the mTLS client cert's public key is
    published in the relying party's own entity statement, so the federation is the
    trust anchor -- there is nothing left for a third-party CA to attest to.
    """
    assert_p256(key)
    private_key = key.private_key
    if private_key is None:
        raise CryptoError("a private key is required to create a self-signed certificate")

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder.sign(private_key, hashes.SHA256())


def attach_x5c(key: ECKey, cert: x509.Certificate) -> ECKey:
    """Return a copy of `key` whose JWK carries the DER cert as `x5c`.

    RFC 7517 requires `x5c` entries to be *standard* base64 (RFC 4648 Section 4), not
    the base64url used everywhere else in JOSE -- an easy copy-paste bug to make given
    every other encode call in this codebase is base64url.
    """
    assert_p256(key)
    der = cert.public_bytes(Encoding.DER)
    encoded = base64.b64encode(der).decode("ascii")

    data = key.as_dict(private=key.is_private)
    data["x5c"] = [encoded]
    return ECKey.import_key(data)


def public_jwks(keys: Iterable[ECKey]) -> dict:
    """Render `keys` as a public JWKS document: `{"keys": [...]}` with no `d` members.

    This dict is destined to be published on the public internet as the entity
    statement's `jwks`, so the "no private key material" check is asserted explicitly
    rather than just trusted to `as_dict(private=False)` alone.
    """
    rendered = []
    for key in keys:
        assert_p256(key)
        data = key.as_dict(private=False)
        if "d" in data:
            raise CryptoError("refusing to publish a JWKS entry that still carries 'd'")
        rendered.append(data)
    return {"keys": rendered}


def private_jwks(keys: Iterable[ECKey]) -> dict:
    """Render `keys` as a private JWKS document, `d` included. For secret storage only."""
    rendered = []
    for key in keys:
        assert_p256(key)
        if not key.is_private:
            raise CryptoError("cannot render a private JWKS entry from a public-only key")
        rendered.append(key.as_dict(private=True))
    return {"keys": rendered}


def load_jwks(data: dict | str) -> KeySet:
    """Parse a JWKS document (dict, or JSON text) into a joserfc KeySet."""
    parsed = json.loads(data) if isinstance(data, str) else data
    return KeySet.import_key_set(parsed)

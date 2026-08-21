"""materialize_keypair's file permissions, and that build_mtls_context/mtls_client load
the resulting files without raising. No real network calls -- construction only.
"""

import ssl
import stat
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from gesundheitsid.crypto.keys import KeyPurpose, generate_p256_key, generate_self_signed_cert
from gesundheitsid.crypto.mtls import (
    DEFAULT_TIMEOUT,
    build_mtls_context,
    materialize_keypair,
    mtls_client,
    plain_client,
)


def _pem_keypair() -> tuple[bytes, bytes]:
    key = generate_p256_key(KeyPurpose.MTLS_CLIENT)
    cert = generate_self_signed_cert(key, subject_cn="rp.example.com", valid_days=30)
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = key.private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    return cert_pem, key_pem


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_materialize_keypair_writes_files_with_mode_0600(tmp_path: Path) -> None:
    cert_pem, key_pem = _pem_keypair()
    directory = tmp_path / "secrets"

    cert_path, key_path = materialize_keypair(cert_pem, key_pem, directory)

    assert cert_path.read_bytes() == cert_pem
    assert key_path.read_bytes() == key_pem
    assert _mode(cert_path) == 0o600
    assert _mode(key_path) == 0o600
    assert _mode(directory) == 0o700


def test_materialize_keypair_creates_missing_parent_directories(tmp_path: Path) -> None:
    cert_pem, key_pem = _pem_keypair()
    directory = tmp_path / "nested" / "secrets"

    cert_path, key_path = materialize_keypair(cert_pem, key_pem, directory)

    assert cert_path.exists()
    assert key_path.exists()


def test_build_mtls_context_loads_the_materialized_keypair_without_raising(tmp_path: Path) -> None:
    cert_pem, key_pem = _pem_keypair()
    cert_path, key_path = materialize_keypair(cert_pem, key_pem, tmp_path / "secrets")

    context = build_mtls_context(cert_path, key_path)

    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_mtls_client_and_plain_client_use_independent_clients(tmp_path: Path) -> None:
    cert_pem, key_pem = _pem_keypair()
    cert_path, key_path = materialize_keypair(cert_pem, key_pem, tmp_path / "secrets")

    with mtls_client(cert_path, key_path) as with_cert, plain_client() as without_cert:
        assert with_cert is not without_cert
        # separate httpx.Client instances imply separate connection pools/transports --
        # the mTLS cert must never leak onto the plain client's connections.
        assert with_cert._transport is not without_cert._transport


def test_both_clients_carry_an_explicit_timeout(tmp_path: Path) -> None:
    """httpx's own default is a library default, not a decision. These calls cross the public
    internet to gematik and to ~130 insurer IdPs inside a request a person is waiting on, so an
    accidental timeout is a real availability risk."""
    cert_pem, key_pem = _pem_keypair()
    cert_path, key_path = materialize_keypair(cert_pem, key_pem, tmp_path / "secrets")

    with mtls_client(cert_path, key_path) as with_cert, plain_client() as without_cert:
        for client in (with_cert, without_cert):
            assert client.timeout == DEFAULT_TIMEOUT
            assert client.timeout.connect == 5.0
            assert client.timeout.read == 15.0


def test_an_explicit_timeout_argument_still_wins(tmp_path: Path) -> None:
    """The default must be a default, not a ceiling -- a caller facing a slow counterparty has to
    be able to override it without reaching past the factory into httpx."""
    cert_pem, key_pem = _pem_keypair()
    cert_path, key_path = materialize_keypair(cert_pem, key_pem, tmp_path / "secrets")
    override = httpx.Timeout(1.0)

    with mtls_client(cert_path, key_path, timeout=override) as with_cert, plain_client(timeout=override) as plain:
        assert with_cert.timeout == override
        assert plain.timeout == override

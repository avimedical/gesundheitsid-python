"""Generate a throwaway CA + `localhost` server certificate for the local federation.

`resolve_trust_chain` refuses any issuer that is not https (see its `_validate_subject_issuer`),
and that refusal is a security control worth keeping exactly as production runs it. gematik's
reference federation speaks plain HTTP, so rather than adding an "allow http in tests" switch --
which is precisely the kind of flag that later gets set in production -- the integration setup
puts a TLS terminator in front of both services and lets the real code path run unmodified.

Writes into `.local-federation/` (gitignored). The key material here is worthless by
construction: it is regenerated on demand, never leaves the machine, and is trusted only by a
test process that opts in via SSL_CERT_FILE.
"""

from __future__ import annotations

import datetime
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT_DIR = pathlib.Path(__file__).resolve().parent.parent / ".local-federation"
VALIDITY_DAYS = 30


def _write(path: pathlib.Path, data: bytes, *, private: bool) -> None:
    path.write_bytes(data)
    path.chmod(0o600 if private else 0o644)


def main() -> int:
    OUT_DIR.mkdir(exist_ok=True)
    now = datetime.datetime.now(datetime.UTC)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gesundheitsid local federation CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        # Python 3.14's verifier is stricter than curl's and rejects a CA that omits either of
        # these: without SubjectKeyIdentifier it reports "Missing Authority Key Identifier", and
        # without an explicit keyCertSign KeyUsage, "Path length given without key usage keyCertSign".
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gsi.test")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(
            # `.gsi.test` -- not `.local` -- names: see docker-compose.yml's top comment
            # on ISSUER_IDP_01 for why (macOS mDNSResponder intercepts `.local` lookups;
            # `.test` is IANA-reserved for exactly this, per RFC 6761). One server
            # certificate covers all three names because one nginx TLS terminator (see
            # docker/local-federation/nginx.conf) fronts all three vhosts.
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("fedmaster.gsi.test"),
                    x509.DNSName("idp.gsi.test"),
                    x509.DNSName("rp.gsi.test"),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
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
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    _write(OUT_DIR / "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM), private=False)
    _write(OUT_DIR / "server.pem", server_cert.public_bytes(serialization.Encoding.PEM), private=False)
    _write(
        OUT_DIR / "server.key",
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private=True,
    )
    print(f"wrote ca.pem, server.pem, server.key to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

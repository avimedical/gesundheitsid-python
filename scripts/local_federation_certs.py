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
import shutil
import subprocess
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
            # `.gsi.test`, not `.local`: macOS mDNSResponder intercepts `.local`, and `.test` is
            # IANA-reserved (RFC 6761). One certificate covers all three names; one nginx fronts them.
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

    _write_java_truststore(OUT_DIR / "ca.pem", OUT_DIR / "truststore.p12")
    return 0


#: password for the throwaway PKCS12 truststore below. Not a secret: the store holds
#: nothing but a public CA certificate that is itself worthless (see module docstring),
#: and JDK keystores require SOME password to open even for read-only trust operations.
_TRUSTSTORE_PASSWORD = "changeit"


def _write_java_truststore(ca_pem_path: pathlib.Path, out_path: pathlib.Path) -> None:
    """Import `ca_pem_path` into a PKCS12 file gsi-server's JVM can use as
    `-Djavax.net.ssl.trustStore`.

    Why this exists: gsi-server calls OUT over https too -- fetching the fedmaster's
    federation_fetch_endpoint, and (once a relying party is registered) that relying
    party's own entity statement -- using Java's platform default SSLContext, which
    trusts only the JDK's built-in public CA bundle. In gematik's real environment every
    counterparty's certificate chains to a publicly trusted CA, so this is invisible; our
    throwaway CA is not publicly trusted anywhere, so those calls fail
    `SSLHandshakeException: PKIX path building failed` against the local federation
    (confirmed empirically -- this is real gsi-server behavior, not a guess, and it does
    NOT show up until something actually exercises those outbound calls, i.e. not until
    PAR is attempted).
    `cryptography`'s own `pkcs12.serialize_key_and_certificates` cannot produce a
    JVM-loadable *trust* store on its own: a `cas=[...]` argument with no key/cert only
    embeds those certificates as part of a key's chain, never as a standalone
    `trustedCertEntry` -- verified empirically (`keytool -list` reported "0 entries" on
    such a file). `keytool -importcert` is what actually creates a `trustedCertEntry`.

    Requires a JDK's `keytool` on PATH -- already a prerequisite for this repository's
    documented gsi-server/gsi-fedmaster image build (see docs/local-federation.md), so
    this does not add a new dependency for anyone doing the full data-plane setup. Skips
    (with a clear message, not a hard failure) when `keytool` is unavailable -- the
    trust-plane-only setup this script has always supported must keep working without a
    JDK installed at all.
    """
    keytool = shutil.which("keytool")
    if keytool is None:
        print(
            "keytool not found on PATH -- skipped writing truststore.p12. "
            "gsi-server's OUTBOUND https calls (to the fedmaster, and to a registered "
            "relying party) will fail PKIX validation against this CA until you install "
            "a JDK and rerun this script; the trust-plane-only setup is unaffected."
        )
        return
    if out_path.exists():
        out_path.unlink()
    subprocess.run(
        [
            keytool,
            "-importcert",
            "-noprompt",
            "-alias",
            "gesundheitsid-local-federation-ca",
            "-file",
            str(ca_pem_path),
            "-keystore",
            str(out_path),
            "-storetype",
            "PKCS12",
            "-storepass",
            _TRUSTSTORE_PASSWORD,
        ],
        check=True,
        capture_output=True,
    )
    out_path.chmod(0o644)  # not a secret -- see _TRUSTSTORE_PASSWORD's own comment
    print(f"wrote {out_path.name} to {out_path.parent} (password: {_TRUSTSTORE_PASSWORD})")


if __name__ == "__main__":
    sys.exit(main())

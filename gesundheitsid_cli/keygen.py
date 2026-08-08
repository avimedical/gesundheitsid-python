"""`gesundheitsid-cli keygen` -- generate the four P-256 keypairs a relying party needs.

Writes one private JWKS file per key purpose plus a combined public bundle and an mTLS
PEM pair, because gematik's registration form and a generic TLS stack each want a
different subset of this material in a different shape.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from joserfc.jwk import ECKey

from gesundheitsid.crypto import (
    MAX_KEY_LIFETIME_DAYS,
    KeyPurpose,
    attach_x5c,
    generate_p256_key,
    generate_self_signed_cert,
    private_jwks,
    public_jwks,
)
from gesundheitsid.errors import GesundheitsIdError

__all__ = ["KeygenResult", "add_subparser", "generate_keys", "public_key_pem", "run", "slug_for"]

# One JWKS file per purpose. The prefix is what ends up in the filename gematik / a TLS
# stack actually sees, so it is kept stable even if KeyPurpose's own string values change.
_FILENAME_PREFIXES: dict[KeyPurpose, str] = {
    KeyPurpose.ENTITY_STATEMENT_SIG: "es_sig",
    KeyPurpose.MTLS_CLIENT: "mtls",
    KeyPurpose.IDTOKEN_ENC: "idtoken_enc",
    KeyPurpose.DOWNSTREAM_SIG: "downstream_sig",
}

# Purposes bundled into the combined public JWKS -- everything the federation is allowed to
# see. DOWNSTREAM_SIG is deliberately excluded: it signs tokens for this RP's own clients
# and is never published anywhere.
_PUBLIC_BUNDLE_PURPOSES = (KeyPurpose.ENTITY_STATEMENT_SIG, KeyPurpose.MTLS_CLIENT, KeyPurpose.IDTOKEN_ENC)

_PRIVATE_FILE_MODE = 0o600
_PUBLIC_FILE_MODE = 0o644


@dataclass(frozen=True)
class KeygenResult:
    """Everything `run()` needs to print after a successful `generate_keys()` call."""

    out_dir: Path
    written_files: list[Path]
    entity_statement_kid: str
    entity_statement_public_pem: str


def slug_for(issuer_uri: str) -> str:
    """Turn an issuer URI into a filesystem-safe slug: scheme stripped, non-alphanumerics -> '_'."""
    without_scheme = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", issuer_uri)
    return re.sub(r"[^A-Za-z0-9]+", "_", without_scheme).strip("_")


def public_key_pem(key: ECKey) -> str:
    """Render an EC JWK's public key as a PEM SubjectPublicKeyInfo block.

    Works whether `key` is public-only or carries a private component -- joserfc's
    `key.public_key` always returns just the public half, so this can never leak `d` even
    if it is accidentally called on a private key.
    """
    return key.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _write(path: Path, content: bytes, *, mode: int) -> None:
    """Create-or-truncate `path` with `mode` set explicitly.

    `os.open`'s requested mode is masked by umask, so the follow-up `os.chmod` is required
    to actually land on 0600 for private files rather than whatever umask allows.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def generate_keys(
    *,
    issuer_uri: str,
    out_dir: Path,
    valid_days: int = MAX_KEY_LIFETIME_DAYS,
    force: bool = False,
) -> KeygenResult:
    """Generate the four keypairs for `issuer_uri` and write them under `out_dir`.

    Every planned output path is checked for a pre-existing file *before* anything is
    written, and only then does the actual writing start -- so a refusal (no `force`)
    never leaves `out_dir` with a mix of fresh and stale key files.
    """
    host = urlparse(issuer_uri).hostname
    if not host:
        raise GesundheitsIdError(f"could not determine a host from --issuer-uri {issuer_uri!r}")
    slug = slug_for(issuer_uri)

    keys: dict[KeyPurpose, ECKey] = {purpose: generate_p256_key(purpose) for purpose in KeyPurpose}

    # The mTLS key is the only one that also needs a self-signed cert attached as x5c --
    # a plain P-256 JWK alone is not enough for `ssl.SSLContext.load_cert_chain`.
    mtls_key = keys[KeyPurpose.MTLS_CLIENT]
    cert = generate_self_signed_cert(mtls_key, subject_cn=host, valid_days=valid_days)
    mtls_key = attach_x5c(mtls_key, cert)
    keys[KeyPurpose.MTLS_CLIENT] = mtls_key

    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)  # mkdir's requested mode is masked by umask; enforce it explicitly

    planned: list[tuple[Path, bytes, int]] = []
    for purpose, key in keys.items():
        path = out_dir / f"{_FILENAME_PREFIXES[purpose]}_{slug}_jwks.json"
        content = json.dumps(private_jwks([key]), indent=2).encode("utf-8") + b"\n"
        planned.append((path, content, _PRIVATE_FILE_MODE))

    public_bundle = public_jwks([keys[purpose] for purpose in _PUBLIC_BUNDLE_PURPOSES])
    public_bundle_path = out_dir / f"{slug}_public_jwks.json"
    planned.append((public_bundle_path, json.dumps(public_bundle, indent=2).encode("utf-8") + b"\n", _PUBLIC_FILE_MODE))

    private_key = mtls_key.private_key
    if private_key is None:  # pragma: no cover -- generate_p256_key always returns a private key
        raise GesundheitsIdError("mTLS key unexpectedly has no private component")
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    planned.append((out_dir / f"mtls_{slug}_cert.pem", cert_pem, _PUBLIC_FILE_MODE))
    planned.append((out_dir / f"mtls_{slug}_key.pem", key_pem, _PRIVATE_FILE_MODE))

    if not force:
        for path, _content, _mode in planned:
            if path.exists():
                raise GesundheitsIdError(f"refusing to overwrite existing file {path} (use --force)")

    written: list[Path] = []
    for path, content, mode in planned:
        _write(path, content, mode=mode)
        written.append(path)

    es_key = keys[KeyPurpose.ENTITY_STATEMENT_SIG]
    return KeygenResult(
        out_dir=out_dir,
        written_files=written,
        entity_statement_kid=es_key.kid,
        entity_statement_public_pem=public_key_pem(es_key),
    )


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "keygen",
        help="generate the four P-256 keypairs a GesundheitsID relying party needs",
    )
    parser.add_argument("--issuer-uri", required=True, help="this relying party's entity statement issuer URI")
    parser.add_argument("--out-dir", default=".", help="directory to write key files into (default: %(default)s)")
    parser.add_argument(
        "--valid-days",
        type=int,
        default=MAX_KEY_LIFETIME_DAYS,
        help="mTLS certificate validity in days (default: %(default)s, gemSpec_IDP_Sek's cap)",
    )
    parser.add_argument("--force", action="store_true", help="overwrite existing files instead of refusing")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    result = generate_keys(
        issuer_uri=args.issuer_uri,
        out_dir=Path(args.out_dir),
        valid_days=args.valid_days,
        force=args.force,
    )

    print(f"Wrote {len(result.written_files)} files to {result.out_dir}:")
    for path in result.written_files:
        print(f"  {path}")

    print()
    print("Entity-statement signing key -- give gematik exactly these two values:")
    print(f"  KID: {result.entity_statement_kid}")
    print(result.entity_statement_public_pem)

    print(
        "WARNING: the *_jwks.json and mtls_*_key.pem files above contain private key "
        "material. Never commit them; load them from a secret manager at runtime."
    )
    return 0

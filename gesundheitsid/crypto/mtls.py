"""mTLS client construction for sectoral IdP PAR/token endpoints.

INVARIANT: the client certificate built here must only ever be presented to a sectoral
IdP's PAR/token endpoints, never to the Federation Master or anywhere else. What the
specs actually require is narrow -- `self_signed_tls_client_auth` is the client
authentication method for the sectoral IdP's PAR and token endpoints -- so presenting
the certificate anywhere else is at best unnecessary and at worst leaks a credential to
a party with no reason to see it. (Whether the Federation Master would *reject* a client
certificate is not something this project has verified; the rule here is least
privilege, not a claim about their server config.)

`mtls_client` and `plain_client` each own a separate `httpx.Client` with a separate
connection pool; never share one client's transport between the two call sites, or the
invariant silently stops holding the moment connection pooling reuses a socket.

`ssl.SSLContext.load_cert_chain()` only accepts file paths -- there is no in-memory PEM
API in CPython -- so `materialize_keypair` writes key material to disk before
`build_mtls_context` can load it. Point its `directory` at a tmpfs; this module makes no
attempt to avoid touching a persistent disk itself.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import httpx

__all__ = [
    "materialize_keypair",
    "build_mtls_context",
    "mtls_client",
    "plain_client",
]

_CERT_FILENAME = "client-cert.pem"
_KEY_FILENAME = "client-key.pem"


def materialize_keypair(cert_pem: bytes, key_pem: bytes, directory: Path) -> tuple[Path, Path]:
    """Write `cert_pem`/`key_pem` into `directory` with mode 0600, creating it (0700) if needed.

    Point `directory` at a tmpfs (e.g. a Kubernetes `emptyDir` with `medium: Memory`) --
    this is the only place the private key touches a filesystem at all, and it exists
    solely because `ssl.SSLContext.load_cert_chain()` requires file paths.
    """
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)  # mkdir's requested mode is masked by umask; enforce it explicitly

    cert_path = directory / _CERT_FILENAME
    key_path = directory / _KEY_FILENAME

    for path, content in ((cert_path, cert_pem), (key_path, key_pem)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        os.chmod(path, 0o600)  # same umask concern as the directory above

    return cert_path, key_path


def build_mtls_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    """Build a client SSLContext presenting `cert_path`/`key_path`.

    Hostname checking and certificate verification are left ON -- this context talks to
    real public TLS endpoints, not a local test double.
    """
    context = ssl.create_default_context()
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def mtls_client(cert_path: Path, key_path: Path, **kwargs: object) -> httpx.Client:
    """An httpx.Client presenting the mTLS client cert. Sectoral IdP PAR/token calls only."""
    context = build_mtls_context(cert_path, key_path)
    return httpx.Client(verify=context, **kwargs)


def plain_client(**kwargs: object) -> httpx.Client:
    """An httpx.Client with no client certificate -- the Federation Master, and everything
    else that must never see the mTLS client cert, goes through this one instead."""
    return httpx.Client(**kwargs)

"""Fixtures for the tests that run against gematik's real reference federation.

Everything else in this suite mocks HTTP with `respx`, which means the client and its fixtures
can only ever agree with each other. That is not a hypothetical weakness: it hid wrong endpoint
paths, a wrong idp_list array key, and a trust chain that discarded the IdP's metadata -- three
defects that made a real login impossible while 223 unit tests passed. These tests exist to be
the one place where the counterparty is not us.

Requires the local federation from `docs/local-federation.md`:

    uv run python scripts/local_federation_certs.py
    docker compose up -d
    uv run pytest -m integration

They skip -- never fail -- when it is not running, so a normal checkout is unaffected.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import ssl

import httpx
import pytest

from gesundheitsid.federation import FederationMasterClient
from gesundheitsid.storage import InMemoryStore

#: The https URLs the TLS terminator publishes. gematik's services speak plain HTTP, and
#: `resolve_trust_chain` refuses non-https issuers on purpose -- see
#: docker/local-federation/nginx.conf for why the fix is a proxy, not a bypass flag.
FEDMASTER_URL = os.environ.get("GESUNDHEITSID_IT_FEDMASTER_URL", "https://localhost:8443")
IDP_URL = os.environ.get("GESUNDHEITSID_IT_IDP_URL", "https://localhost:8445")

CA_BUNDLE = pathlib.Path(__file__).resolve().parents[2] / ".local-federation" / "ca.pem"


def _decode_payload(compact_jwt: str) -> dict:
    payload = compact_jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


@pytest.fixture(scope="session")
def local_ca() -> pathlib.Path:
    if not CA_BUNDLE.exists():
        pytest.skip(f"no local CA at {CA_BUNDLE} -- run `uv run python scripts/local_federation_certs.py`")
    return CA_BUNDLE


@pytest.fixture(scope="session")
def http_client(local_ca: pathlib.Path):
    """An httpx client trusting only the local federation's throwaway CA.

    Passed explicitly into the library rather than exported as SSL_CERT_FILE, so trusting this
    CA stays scoped to these tests and cannot leak into anything else the process does.
    """
    context = ssl.create_default_context(cafile=str(local_ca))
    with httpx.Client(verify=context, timeout=10.0) as client:
        yield client


@pytest.fixture(scope="session")
def federation_is_up(http_client: httpx.Client) -> None:
    for name, url in (("gsi-fedmaster", FEDMASTER_URL), ("gsi-server", IDP_URL)):
        try:
            response = http_client.get(f"{url}/.well-known/openid-federation")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            pytest.skip(f"local reference federation not reachable ({name} at {url}): {exc}")


@pytest.fixture(scope="session")
def trust_anchor_jwks(http_client: httpx.Client, federation_is_up: None) -> dict:
    """The Federation Master's public keys.

    In production this is pinned configuration, shipped with the relying party and never
    fetched -- a trust anchor that vouches for itself is not an anchor. Reading it off the
    local fedmaster is a bootstrap convenience that is acceptable ONLY because this federation
    is a disposable one on this machine. Do not copy this pattern into deployment config.
    """
    token = http_client.get(f"{FEDMASTER_URL}/.well-known/openid-federation").text
    return _decode_payload(token)["jwks"]


@pytest.fixture
def fedmaster_client(http_client: httpx.Client, trust_anchor_jwks: dict) -> FederationMasterClient:
    # A fresh store per test: these tests are about what the network really returns, and a
    # shared cache would let one test's fetch satisfy another's assertion.
    return FederationMasterClient(
        FEDMASTER_URL,
        trust_anchor_jwks=trust_anchor_jwks,
        http_client=http_client,
        store=InMemoryStore(),
    )

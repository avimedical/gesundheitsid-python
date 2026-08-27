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
from joserfc.jwk import ECKey

from gesundheitsid.federation import FederationMasterClient, TrustChain, resolve_trust_chain
from gesundheitsid.storage import InMemoryStore
from gesundheitsid_cli.keygen import slug_for

#: The https URLs the TLS terminator publishes - gematik's services speak plain HTTP and
#: resolve_trust_chain refuses non-https issuers on purpose. `.gsi.test` names so they resolve
#: identically on the host and in the containers; macOS intercepts `.local`, `.test` is reserved.
FEDMASTER_URL = os.environ.get("GESUNDHEITSID_IT_FEDMASTER_URL", "https://fedmaster.gsi.test:8443")
IDP_URL = os.environ.get("GESUNDHEITSID_IT_IDP_URL", "https://idp.gsi.test:8445")

CA_BUNDLE = pathlib.Path(__file__).resolve().parents[2] / ".local-federation" / "ca.pem"
RP_KEYS_DIR = pathlib.Path(__file__).resolve().parents[2] / ".local-federation" / "rp"

#: This relying party's issuer, as registered with the local fedmaster -- see
#: docs/local-federation.md's "Registering our relying party". Must match
#: tests/integration/local_federation_settings.py's ISSUER exactly.
RP_ISSUER = os.environ.get("GESUNDHEITSID_IT_RP_ISSUER", "https://rp.gsi.test:8447")
#: gsi-server hardcodes redirect_uris/scope into the statement it issues about ANY relying party,
#: so these are the only values it will ever validate a local PAR against - not our preferences.
REDIRECT_URI = "https://redirect.testsuite.gsi"
SCOPES = ("openid", "urn:telematik:display_name", "urn:telematik:versicherter")
#: gsi-server's test-only auth shortcut mints a real authorization code for any [A-Z] plus 9 digits.
#: NOT a real KVNR: it is that shortcut's own canned, public test value, so the "never log a raw
#: KVNR" rule is not in play here.
TEST_USER_ID = "X110411675"


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


@pytest.fixture(scope="session")
def rp_is_registered(http_client: httpx.Client, federation_is_up: None) -> None:
    """Skip (never fail) the OIDC data-plane tests when this relying party has not been
    generated/registered -- see docs/local-federation.md's "Registering our relying
    party". Distinct from `federation_is_up`: gsi-fedmaster/gsi-server can be up with no
    RP registered at all (that is in fact this repo's default state before you run
    `keygen` and rebuild gsi-fedmaster), which is a normal, un-broken state to skip in.
    """
    if not RP_KEYS_DIR.is_dir():
        pytest.skip(
            f"no local RP keys at {RP_KEYS_DIR} -- run `uv run gesundheitsid-cli keygen "
            f"--issuer-uri={RP_ISSUER} --out-dir={RP_KEYS_DIR}` and register it (see "
            "docs/local-federation.md)"
        )
    try:
        response = http_client.get(f"{RP_ISSUER}/.well-known/openid-federation")
        response.raise_for_status()
    except httpx.HTTPError as exc:
        pytest.skip(
            f"this relying party's dev server is not reachable at {RP_ISSUER} -- run "
            "`DJANGO_SETTINGS_MODULE=tests.integration.local_federation_settings uv run "
            f"python -m django runserver 0.0.0.0:8000` (see docs/local-federation.md): {exc}"
        )


def _load_rp_private_jwk(prefix: str) -> ECKey:
    slug = slug_for(RP_ISSUER)
    path = RP_KEYS_DIR / f"{prefix}_{slug}_jwks.json"
    with path.open() as f:
        return ECKey.import_key(json.load(f)["keys"][0])


@pytest.fixture(scope="session")
def rp_idtoken_enc_key(rp_is_registered: None) -> ECKey:
    """This relying party's own IDTOKEN_ENC private key -- the id_token JWE's recipient.
    Loaded from the same gitignored `.local-federation/rp/` keygen wrote, never a
    freshly-generated one: it must be the exact key gsi-server encrypted against, which
    it read straight out of this RP's own published entity statement."""
    return _load_rp_private_jwk("idtoken_enc")


@pytest.fixture(scope="session")
def rp_mtls_paths(rp_is_registered: None) -> tuple[pathlib.Path, pathlib.Path]:
    """This relying party's own mTLS client certificate/key PEM paths, as written by
    `gesundheitsid-cli keygen`."""
    slug = slug_for(RP_ISSUER)
    cert_path = RP_KEYS_DIR / f"mtls_{slug}_cert.pem"
    key_path = RP_KEYS_DIR / f"mtls_{slug}_key.pem"
    return cert_path, key_path


@pytest.fixture
def mtls_client(local_ca: pathlib.Path, rp_mtls_paths: tuple[pathlib.Path, pathlib.Path]):
    """An httpx.Client presenting this relying party's own mTLS client certificate,
    trusting only the local federation's throwaway CA.

    Deliberately NOT `gesundheitsid.crypto.mtls.mtls_client`: that helper's
    `build_mtls_context` uses `ssl.create_default_context()` with no way to point it at a
    non-system CA (by design -- it talks to real public TLS endpoints in production, see
    that module's docstring), so it cannot trust our throwaway local CA. Building an
    `ssl.SSLContext` combining both concerns (trust the local CA, present our own client
    cert) here does not require touching production code at all -- this is a test-only
    client, structurally equivalent to (but independent of) the production one. Loading
    the client cert onto the context via `load_cert_chain` rather than httpx's own
    `cert=` shorthand, which is deprecated as of httpx 0.28 in favor of exactly this.
    """
    cert_path, key_path = rp_mtls_paths
    context = ssl.create_default_context(cafile=str(local_ca))
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    with httpx.Client(verify=context, timeout=10.0) as client:
        yield client


@pytest.fixture
def trust_chain(fedmaster_client: FederationMasterClient, http_client: httpx.Client) -> TrustChain:
    """The IdP's trust chain, resolved once per test against the real local federation --
    same fresh-store-per-test reasoning as `fedmaster_client` itself."""
    return resolve_trust_chain(subject_issuer=IDP_URL, fedmaster_client=fedmaster_client, http_client=http_client)

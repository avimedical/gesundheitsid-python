"""Django settings for running THIS relying party for real, on the host, against the local
reference federation from `docs/local-federation.md`.

Not a production settings module (that is explicitly a separate, later task -- see the
step-4 commit that added this file) and not `pytest`'s `DJANGO_SETTINGS_MODULE` either
(`pytest.ini` still points at `tests/django/settings.py`, whose keys are freshly generated
per test run and never registered with any federation). This module exists solely so
`gsi-server` -- running in its own container -- has something real to fetch at
`https://rp.gsi.test:8447/.well-known/openid-federation`: the local fedmaster's subordinate
statement about us only carries a metadata overlay (see
`EntityStatementFederationMemberBuilder.buildMetadataForRelyingParty` in gematik's source),
never our actual `jwks` -- `gsi-server` gets our real signing/encryption/mTLS keys by
fetching this relying party's own self-signed entity statement, which only this Django
view (`django_gesundheitsid.views.entity_statement`) can produce.

Run it (after `uv run gesundheitsid-cli keygen --issuer-uri=https://rp.gsi.test:8447
--out-dir=.local-federation/rp` and registering the resulting ES-signing public key with
the local fedmaster -- see docs/local-federation.md):

    DJANGO_SETTINGS_MODULE=tests.integration.local_federation_settings \
        uv run python -m django runserver 0.0.0.0:8000

`0.0.0.0`, not `127.0.0.1`: the request arrives from inside a container (via
`tls-proxy`'s rp.gsi.test:8447 vhost -> host.docker.internal:8000), not from this host's
own loopback.

The keys loaded below are the actual private halves of the public keys baked into the
`gsi-fedmaster` image's classpath (`gsi-fedmaster/src/main/resources/keys/ref-rp-local-es-
sig-pubkey.pem` in the gematik checkout) -- they are NOT fresh throwaway keys the way
`tests/django/settings.py` uses, because `TokenRepositoryRp.fetchAndStoreEntityStmnt`
verifies our self-signed statement against exactly the key the fedmaster was told to
trust. Using different keys here would make gsi-server reject every fetch with a
signature mismatch.
"""

from __future__ import annotations

import base64
import json
import ssl
import tempfile
import urllib.request
from pathlib import Path

from gesundheitsid_cli.keygen import slug_for

BASE_DIR = Path(__file__).resolve().parents[2]
RP_KEYS_DIR = BASE_DIR / ".local-federation" / "rp"
CA_BUNDLE = BASE_DIR / ".local-federation" / "ca.pem"

ISSUER = "https://rp.gsi.test:8447"
FEDMASTER_URL = "https://fedmaster.gsi.test:8443"
#: gematik's reference fedmaster hardcodes this RP metadata for EVERY relying party it
#: vouches for (EntityStatementFederationMemberBuilder.buildMetadataForRelyingParty) --
#: our real redirect_uris/scopes are never consulted, so PAR against the local federation
#: only ever validates against exactly these. See docs/local-federation.md's "OIDC data
#: plane" section.
REDIRECT_URI = "https://redirect.testsuite.gsi"
SCOPES = ["openid", "urn:telematik:display_name", "urn:telematik:versicherter"]

_SLUG = slug_for(ISSUER)


def _load_purpose_jwks(prefix: str) -> dict:
    path = RP_KEYS_DIR / f"{prefix}_{_SLUG}_jwks.json"
    if not path.exists():
        raise RuntimeError(
            f"missing {path} -- run `uv run gesundheitsid-cli keygen --issuer-uri={ISSUER} "
            f"--out-dir={RP_KEYS_DIR}` first (see docs/local-federation.md)"
        )
    return json.loads(path.read_text())


def _fetch_trust_anchor_jwks() -> dict:
    """The local fedmaster's own public keys, fetched (not pinned) purely as a bootstrap
    convenience for this throwaway, disposable federation -- see
    `tests/integration/conftest.py`'s `trust_anchor_jwks` fixture for the same pattern and
    why this is never acceptable for a real deployment."""
    if not CA_BUNDLE.exists():
        raise RuntimeError(f"missing {CA_BUNDLE} -- run `uv run python scripts/local_federation_certs.py` first")
    context = ssl.create_default_context(cafile=str(CA_BUNDLE))
    with urllib.request.urlopen(f"{FEDMASTER_URL}/.well-known/openid-federation", context=context, timeout=10) as resp:
        token = resp.read().decode("ascii")
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return claims["jwks"]


SECRET_KEY = "not-a-secret-only-used-to-run-the-local-federation-dev-server"  # dev-only, never deployed
DEBUG = True
ALLOWED_HOSTS = ["*"]
USE_TZ = True

# Deliberately minimal: this process serves exactly two federation-facing GET endpoints
# (entity_statement, idps) plus the downstream-OIDC endpoints this exercise never drives
# through Django itself (the integration tests call gesundheitsid.oidc's PAR/token/id_token
# functions directly against gsi-server, the same way tests/integration/test_local_federation.py
# calls FederationMasterClient/resolve_trust_chain directly -- see that file's docstring).
# None of `django_gesundheitsid`'s views touch the session, auth, or ORM, so none of
# django.contrib's session/auth/staticfiles/contenttypes apps are needed here, unlike
# tests/django/settings.py (which additionally mounts django.contrib.admin for its own
# unrelated test coverage).
INSTALLED_APPS = ["django_gesundheitsid"]

MIDDLEWARE = []

ROOT_URLCONF = "tests.integration.local_federation_urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(Path(tempfile.gettempdir()) / "gesundheitsid_local_federation.sqlite3"),
    }
}

CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
}

GESUNDHEITSID = {
    "ISSUER": ISSUER,
    "ENVIRONMENT": "TU",  # unused -- FEDERATION_MASTER_URL below overrides it -- but still required
    "FEDERATION_MASTER_URL": FEDMASTER_URL,
    "SCOPES": SCOPES,
    "REDIRECT_URI": REDIRECT_URI,
    "ORGANIZATION_NAME": "gesundheitsid-python local federation RP",
    "CLIENT_NAME": "gesundheitsid-python local federation RP",
    "CONTACTS": ["ops@gesundheitsid-python.invalid"],
    "KEYS": {
        "ENTITY_STATEMENT_SIG": _load_purpose_jwks("es_sig"),
        "MTLS_CLIENT": _load_purpose_jwks("mtls"),
        "IDTOKEN_ENC": _load_purpose_jwks("idtoken_enc"),
        "DOWNSTREAM_SIG": _load_purpose_jwks("downstream_sig"),
    },
    "MTLS_TMP_DIR": str(Path(tempfile.gettempdir()) / "gesundheitsid-local-federation-mtls"),
    "STORE_BACKEND": "memory",
    "TRUST_ANCHOR_JWKS": _fetch_trust_anchor_jwks(),
    "DOWNSTREAM_CLIENTS": [],
    "PAIRWISE_PEPPER": "not-a-secret-pepper-only-used-for-the-local-federation-00",
}

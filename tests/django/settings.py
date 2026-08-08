"""Minimal Django settings for the `django_gesundheitsid` test suite.

Never used outside `pytest` -- `pytest.ini`'s `DJANGO_SETTINGS_MODULE` points here. The
`GESUNDHEITSID` federation material below is a throwaway, real (P-256, self-signed) key
set generated at import time purely so `apps.GesundheitsIdConfig.ready()` has something
valid to parse at Django startup; individual tests that need a specific federation (to
match a `respx`-mocked Federation Master) override it with `pytest.mark.django_db` +
`override_settings` via the fixtures in `conftest.py`, not by editing this file.

The sqlite `transaction_mode: IMMEDIATE` option is required for
`DatabaseStore.pop`'s concurrency test: SQLite's default DEFERRED transactions let two
connections both hold a SHARED read lock (from `select_for_update()`, a no-op on SQLite)
at once, so neither can ever escalate to a write lock -- a self-deadlock that only resolves
by hitting the busy-timeout and raising `OperationalError`, not by one of them losing
cleanly. IMMEDIATE acquires the write lock at BEGIN, so the two transactions are properly
serialized instead of deadlocking. See `tests/django/test_stores.py`.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from gesundheitsid.crypto import (
    KeyPurpose,
    attach_x5c,
    generate_p256_key,
    generate_self_signed_cert,
    private_jwks,
    public_jwks,
)

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = "not-a-secret-only-used-to-run-tests"  # test-only, never deployed
DEBUG = True
ALLOWED_HOSTS = ["*"]
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.admin",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_gesundheitsid",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

ROOT_URLCONF = "tests.django.urls"

# NAME stays ":memory:" -- this settings module is never used for anything but tests, and
# the real (file-based) database the concurrency test needs lives under TEST.NAME instead,
# see the module docstring.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "OPTIONS": {"transaction_mode": "IMMEDIATE"},
        "TEST": {"NAME": str(Path(tempfile.gettempdir()) / "gesundheitsid_django_tests.sqlite3")},
    }
}

CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
}

_es_sig_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
_mtls_key = generate_p256_key(KeyPurpose.MTLS_CLIENT)
_mtls_cert = generate_self_signed_cert(_mtls_key, subject_cn="gesundheitsid.invalid")
_mtls_key = attach_x5c(_mtls_key, _mtls_cert)
_idtoken_enc_key = generate_p256_key(KeyPurpose.IDTOKEN_ENC)
_downstream_sig_key = generate_p256_key(KeyPurpose.DOWNSTREAM_SIG)
_trust_anchor_key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)

GESUNDHEITSID = {
    "ISSUER": "https://gesundheitsid.invalid",
    "ENVIRONMENT": "TU",
    "SCOPES": ["openid", "urn:telematik:display_name", "urn:telematik:versicherter"],
    "REDIRECT_URI": "https://gesundheitsid.invalid/auth/callback",
    "ORGANIZATION_NAME": "Test Relying Party",
    "CLIENT_NAME": "Test Relying Party",
    "CONTACTS": ["ops@gesundheitsid.invalid"],
    "KEYS": {
        "ENTITY_STATEMENT_SIG": private_jwks([_es_sig_key]),
        "MTLS_CLIENT": private_jwks([_mtls_key]),
        "IDTOKEN_ENC": private_jwks([_idtoken_enc_key]),
        "DOWNSTREAM_SIG": private_jwks([_downstream_sig_key]),
    },
    "MTLS_TMP_DIR": str(Path(tempfile.gettempdir()) / "gesundheitsid-mtls-tests"),
    "STORE_BACKEND": "memory",
    "TRUST_ANCHOR_JWKS": public_jwks([_trust_anchor_key]),
    "DOWNSTREAM_CLIENTS": [],
    # Test-only; a real deployment loads this from its secret manager. See
    # GesundheitsIdSettings.pairwise_pepper's docstring for why it is effectively
    # permanent once real accounts exist.
    "PAIRWISE_PEPPER": "not-a-secret-pepper-only-used-to-run-tests-00",
}

"""`GesundheitsIdSettings.from_mapping` validation, called directly against hand-built
mappings -- not through Django's global settings -- so a missing/invalid-config test
never has to break `django.setup()` for the rest of the suite. `apps.GesundheitsIdConfig.
ready()` calling `get_settings()` (exercised implicitly by every other test importing
Django) is what proves the fail-at-startup wiring itself; this file proves the validation
logic underneath it.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured

from django_gesundheitsid.conf import GesundheitsIdSettings, get_settings
from gesundheitsid.crypto import KeyPurpose, generate_p256_key, private_jwks


def test_valid_settings_parse_successfully(gesundheitsid_settings: dict) -> None:
    parsed = GesundheitsIdSettings.from_mapping(gesundheitsid_settings)
    assert parsed.issuer == gesundheitsid_settings["ISSUER"]
    assert parsed.environment.value == "TU"
    assert parsed.store_backend.value == "memory"


@pytest.mark.parametrize(
    "missing_key",
    [
        "ISSUER",
        "ENVIRONMENT",
        "SCOPES",
        "REDIRECT_URI",
        "ORGANIZATION_NAME",
        "CLIENT_NAME",
        "CONTACTS",
        "KEYS",
        "MTLS_TMP_DIR",
        "STORE_BACKEND",
        "TRUST_ANCHOR_JWKS",
    ],
)
def test_missing_required_setting_fails_fast(gesundheitsid_settings: dict, missing_key: str) -> None:
    incomplete = dict(gesundheitsid_settings)
    del incomplete[missing_key]

    with pytest.raises(ImproperlyConfigured, match=missing_key):
        GesundheitsIdSettings.from_mapping(incomplete)


def test_missing_key_purpose_fails_fast(gesundheitsid_settings: dict) -> None:
    broken = dict(gesundheitsid_settings)
    broken["KEYS"] = {k: v for k, v in broken["KEYS"].items() if k != "DOWNSTREAM_SIG"}

    with pytest.raises(ImproperlyConfigured, match="DOWNSTREAM_SIG"):
        GesundheitsIdSettings.from_mapping(broken)


def test_invalid_environment_fails_fast(gesundheitsid_settings: dict) -> None:
    broken = {**gesundheitsid_settings, "ENVIRONMENT": "NOT_A_REAL_ENVIRONMENT"}

    with pytest.raises(ImproperlyConfigured, match="ENVIRONMENT"):
        GesundheitsIdSettings.from_mapping(broken)


def test_invalid_store_backend_fails_fast(gesundheitsid_settings: dict) -> None:
    broken = {**gesundheitsid_settings, "STORE_BACKEND": "not-a-real-backend"}

    with pytest.raises(ImproperlyConfigured, match="STORE_BACKEND"):
        GesundheitsIdSettings.from_mapping(broken)


def test_non_https_issuer_fails_fast(gesundheitsid_settings: dict) -> None:
    broken = {**gesundheitsid_settings, "ISSUER": "http://not-https.example.com"}

    with pytest.raises(ImproperlyConfigured, match="ISSUER"):
        GesundheitsIdSettings.from_mapping(broken)


def test_scopes_without_openid_fails_fast(gesundheitsid_settings: dict) -> None:
    broken = {**gesundheitsid_settings, "SCOPES": ["urn:telematik:versicherter"]}

    with pytest.raises(ImproperlyConfigured, match="openid"):
        GesundheitsIdSettings.from_mapping(broken)


def test_mtls_client_key_without_x5c_fails_fast(gesundheitsid_settings: dict) -> None:
    # The fixture's own MTLS_CLIENT key carries x5c; generate a fresh one that doesn't.
    bare_key = generate_p256_key(KeyPurpose.MTLS_CLIENT)
    broken_keys = {**gesundheitsid_settings["KEYS"], "MTLS_CLIENT": private_jwks([bare_key])}
    broken = {**gesundheitsid_settings, "KEYS": broken_keys}

    with pytest.raises(ImproperlyConfigured, match="x5c"):
        GesundheitsIdSettings.from_mapping(broken)


def test_downstream_client_with_bad_auth_method_fails_fast(gesundheitsid_settings: dict) -> None:
    broken = {
        **gesundheitsid_settings,
        "DOWNSTREAM_CLIENTS": [
            {
                "CLIENT_ID": "some-client",
                "REDIRECT_URIS": ["https://example.com/callback"],
                "TOKEN_ENDPOINT_AUTH_METHOD": "client_secret_basic",
            }
        ],
    }

    with pytest.raises(ImproperlyConfigured, match="TOKEN_ENDPOINT_AUTH_METHOD"):
        GesundheitsIdSettings.from_mapping(broken)


def test_get_settings_raises_when_gesundheitsid_setting_is_absent(settings) -> None:
    del settings.GESUNDHEITSID

    with pytest.raises(ImproperlyConfigured, match="GESUNDHEITSID"):
        get_settings()


def test_get_settings_is_cached_until_settings_change(settings) -> None:
    first = get_settings()
    second = get_settings()
    assert first is second

    settings.GESUNDHEITSID = {**settings.GESUNDHEITSID, "CLIENT_NAME": "A Different Name"}

    third = get_settings()
    assert third is not first
    assert third.client_name == "A Different Name"

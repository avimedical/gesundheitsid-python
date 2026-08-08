"""fedreg: XML shape/fields, KID/PEM provenance, and each documented validation rule."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
from joserfc.jwk import ECKey

from gesundheitsid.crypto import KeyPurpose, generate_p256_key, private_jwks
from gesundheitsid.errors import GesundheitsIdError
from gesundheitsid_cli.fedreg import _load_entity_statement_key, _resolve_scopes, build_registration_xml

_ISSUER = "https://gid.example.com"

_DOCUMENTED_FIELDS = {
    "teilnehmertyp",
    "betriebsumgebung",
    "kontaktemail",
    "vfsbestaetigung",
    "zuweisungsgruppe",
    "memberid",
    "organisationsname",
    "fachdienstname",
    "fachdiensturi",
    "scopes",
    "claims",
    "redirect_uris",
    "publickeysjwt",
}


@pytest.fixture
def jwks_path(tmp_path: Path) -> Path:
    key = generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG)
    path = tmp_path / "es_sig_jwks.json"
    path.write_text(json.dumps(private_jwks([key])))
    return path


@pytest.fixture
def signing_key(jwks_path: Path) -> ECKey:
    return _load_entity_statement_key(jwks_path)


def _base_kwargs(signing_key: ECKey) -> dict[str, Any]:
    return {
        "environment": "TU",
        "issuer_uri": _ISSUER,
        "member_id": "FDexample0112TU",
        "contact_email": "a@example.com",
        "organization_name": "Example GmbH",
        "fachdienst_name": "Example Fachdienst",
        "scopes": ["openid", "urn:telematik:versicherter"],
        "redirect_uris": ["https://gid.example.com/callback"],
        "signing_key": signing_key,
        "vfs_bestaetigung": "",
        "zuweisungsgruppe": "",
    }


def test_load_entity_statement_key_rejects_a_multi_key_jwks(tmp_path: Path) -> None:
    keys = [generate_p256_key(KeyPurpose.ENTITY_STATEMENT_SIG) for _ in range(2)]
    path = tmp_path / "multi_jwks.json"
    path.write_text(json.dumps(private_jwks(keys)))

    with pytest.raises(GesundheitsIdError, match="exactly one key"):
        _load_entity_statement_key(path)


def test_load_entity_statement_key_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(GesundheitsIdError):
        _load_entity_statement_key(tmp_path / "does-not-exist.json")


def test_resolve_scopes_falls_back_to_the_documented_default() -> None:
    scopes = _resolve_scopes(None)
    assert scopes == ["openid", "urn:telematik:display_name", "urn:telematik:versicherter"]


def test_resolve_scopes_accepts_repeated_and_comma_separated_flags() -> None:
    scopes = _resolve_scopes(["openid", "urn:telematik:versicherter,urn:telematik:email"])
    assert scopes == ["openid", "urn:telematik:versicherter", "urn:telematik:email"]


def test_build_registration_xml_is_well_formed_and_has_every_documented_field(signing_key: ECKey) -> None:
    xml_text, warnings = build_registration_xml(**_base_kwargs(signing_key))

    root = ET.fromstring(xml_text)  # raises if malformed
    assert root.tag == "registrierungtifoederation"
    assert warnings == []

    tags = {child.tag for child in root}
    assert tags == _DOCUMENTED_FIELDS

    assert root.find("teilnehmertyp").text == "Fachdienst"
    assert root.find("betriebsumgebung").text == "TU"
    assert root.find("kontaktemail").text == "a@example.com"
    assert root.find("memberid").text == "FDexample0112TU"
    assert root.find("fachdiensturi").text == _ISSUER
    assert [scope.text for scope in root.find("scopes")] == ["openid", "urn:telematik:versicherter"]
    assert root.find("redirect_uris/redirect_uri").text == "https://gid.example.com/callback"


def test_kid_and_key_come_from_the_supplied_jwks(signing_key: ECKey) -> None:
    xml_text, _ = build_registration_xml(**_base_kwargs(signing_key))
    root = ET.fromstring(xml_text)

    assert root.find("publickeysjwt/publickey/kid").text == signing_key.kid
    key_pem = root.find("publickeysjwt/publickey/key").text
    assert "-----BEGIN PUBLIC KEY-----" in key_pem
    assert "-----END PUBLIC KEY-----" in key_pem


def test_rejects_non_https_issuer(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["issuer_uri"] = "http://gid.example.com"
    with pytest.raises(GesundheitsIdError, match="https"):
        build_registration_xml(**kwargs)


def test_rejects_issuer_with_a_query_string(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["issuer_uri"] = "https://gid.example.com?foo=bar"
    with pytest.raises(GesundheitsIdError, match="query string"):
        build_registration_xml(**kwargs)


def test_rejects_issuer_with_a_fragment(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["issuer_uri"] = "https://gid.example.com#frag"
    with pytest.raises(GesundheitsIdError, match="fragment"):
        build_registration_xml(**kwargs)


def test_rejects_a_redirect_uri_on_a_different_origin(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["redirect_uris"] = ["https://evil.example.com/callback"]
    with pytest.raises(GesundheitsIdError, match="origin"):
        build_registration_xml(**kwargs)


def test_rejects_a_non_https_redirect_uri(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["redirect_uris"] = ["http://gid.example.com/callback"]
    with pytest.raises(GesundheitsIdError, match="https"):
        build_registration_xml(**kwargs)


def test_rejects_scopes_missing_openid(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["scopes"] = ["urn:telematik:versicherter"]
    with pytest.raises(GesundheitsIdError, match="openid"):
        build_registration_xml(**kwargs)


def test_pu_without_vfs_bestaetigung_is_rejected(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["environment"] = "PU"
    with pytest.raises(GesundheitsIdError, match="vfs-bestaetigung"):
        build_registration_xml(**kwargs)


def test_pu_with_vfs_bestaetigung_succeeds_with_no_warning(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["environment"] = "PU"
    kwargs["vfs_bestaetigung"] = "some-confirmation-key"
    _, warnings = build_registration_xml(**kwargs)
    assert warnings == []


def test_vfs_bestaetigung_outside_pu_is_a_warning_not_an_error(signing_key: ECKey) -> None:
    kwargs = _base_kwargs(signing_key)
    kwargs["vfs_bestaetigung"] = "some-confirmation-key"
    _, warnings = build_registration_xml(**kwargs)
    assert len(warnings) == 1
    assert "PU" in warnings[0]

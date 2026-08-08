"""keygen: file layout, permissions, JWKS validity, x5c presence, and --force semantics."""

import json
import stat
from pathlib import Path

import pytest
from joserfc.jwk import ECKey

from gesundheitsid.crypto import load_jwks
from gesundheitsid.errors import GesundheitsIdError
from gesundheitsid_cli.keygen import generate_keys, slug_for

_ISSUER = "https://gid.example.com"
_SLUG = "gid_example_com"

_PRIVATE_FILENAMES = [
    f"es_sig_{_SLUG}_jwks.json",
    f"mtls_{_SLUG}_jwks.json",
    f"idtoken_enc_{_SLUG}_jwks.json",
    f"downstream_sig_{_SLUG}_jwks.json",
    f"mtls_{_SLUG}_key.pem",
]
_PUBLIC_FILENAMES = [f"{_SLUG}_public_jwks.json", f"mtls_{_SLUG}_cert.pem"]


def test_slug_for_strips_scheme_and_replaces_non_alphanumerics() -> None:
    assert slug_for("https://gid.example.com") == _SLUG
    assert slug_for("https://gid.example.com:8443/foo") == "gid_example_com_8443_foo"


def test_generate_keys_writes_exactly_the_expected_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    result = generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)

    written_names = {path.name for path in result.written_files}
    assert written_names == set(_PRIVATE_FILENAMES) | set(_PUBLIC_FILENAMES)
    for name in written_names:
        assert (out_dir / name).is_file()


def test_generate_keys_creates_out_dir_with_mode_0700(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700


@pytest.mark.parametrize("filename", _PRIVATE_FILENAMES)
def test_files_with_private_material_are_mode_0600(tmp_path: Path, filename: str) -> None:
    out_dir = tmp_path / "keys"
    generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    assert stat.S_IMODE((out_dir / filename).stat().st_mode) == 0o600


@pytest.mark.parametrize("filename", _PUBLIC_FILENAMES)
def test_public_only_files_are_not_mode_0600(tmp_path: Path, filename: str) -> None:
    out_dir = tmp_path / "keys"
    generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    assert stat.S_IMODE((out_dir / filename).stat().st_mode) != 0o600


def test_every_jwks_file_parses_back_through_load_jwks(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    result = generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    jwks_files = [path for path in result.written_files if path.name.endswith("_jwks.json")]
    assert len(jwks_files) == 5  # 4 private + 1 public bundle
    for path in jwks_files:
        key_set = load_jwks(path.read_text())
        assert len(key_set.keys) >= 1


def test_mtls_key_carries_a_usable_x5c(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    doc = json.loads((out_dir / f"mtls_{_SLUG}_jwks.json").read_text())
    key = doc["keys"][0]
    assert len(key.get("x5c", [])) == 1
    ECKey.import_key(key)  # round-trips through joserfc without error


def test_public_bundle_has_three_keys_and_no_private_material(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    doc = json.loads((out_dir / f"{_SLUG}_public_jwks.json").read_text())
    assert len(doc["keys"]) == 3
    for key in doc["keys"]:
        assert "d" not in key


def test_result_reports_entity_statement_kid_and_pem(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    result = generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    assert result.entity_statement_kid
    assert "-----BEGIN PUBLIC KEY-----" in result.entity_statement_public_pem
    assert "-----END PUBLIC KEY-----" in result.entity_statement_public_pem


def test_refuses_to_overwrite_without_force_and_names_the_blocking_file(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)

    with pytest.raises(GesundheitsIdError, match=f"es_sig_{_SLUG}_jwks.json"):
        generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)


def test_force_overwrites_existing_files_with_freshly_generated_keys(tmp_path: Path) -> None:
    out_dir = tmp_path / "keys"
    first = generate_keys(issuer_uri=_ISSUER, out_dir=out_dir)
    second = generate_keys(issuer_uri=_ISSUER, out_dir=out_dir, force=True)

    assert first.entity_statement_kid != second.entity_statement_kid


def test_generate_keys_rejects_an_issuer_uri_without_a_host(tmp_path: Path) -> None:
    with pytest.raises(GesundheitsIdError):
        generate_keys(issuer_uri="not-a-url", out_dir=tmp_path / "keys")

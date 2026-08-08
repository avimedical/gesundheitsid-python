"""main(): exit codes and stderr-not-a-traceback behavior across both subcommands."""

from pathlib import Path

import pytest

from gesundheitsid_cli.__main__ import main

_ISSUER = "https://gid.example.com"
_SLUG = "gid_example_com"


def test_keygen_returns_zero_and_writes_files(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    out_dir = tmp_path / "keys"
    code = main(["keygen", f"--issuer-uri={_ISSUER}", f"--out-dir={out_dir}"])

    assert code == 0
    captured = capsys.readouterr()
    assert "KID" in captured.out
    assert "never be committed" not in captured.out  # sanity: warning text is worded, not this literal
    assert any(out_dir.iterdir())


def test_keygen_collision_is_reported_on_stderr_not_a_traceback(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    out_dir = tmp_path / "keys"
    out_dir.mkdir()
    (out_dir / f"es_sig_{_SLUG}_jwks.json").write_text("{}")

    code = main(["keygen", f"--issuer-uri={_ISSUER}", f"--out-dir={out_dir}"])

    assert code != 0
    captured = capsys.readouterr()
    assert captured.err.startswith("error:")
    assert "Traceback" not in captured.err


def test_fedreg_returns_zero_and_prints_xml(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    out_dir = tmp_path / "keys"
    main(["keygen", f"--issuer-uri={_ISSUER}", f"--out-dir={out_dir}"])
    jwks_path = out_dir / f"es_sig_{_SLUG}_jwks.json"
    capsys.readouterr()  # discard keygen's own output

    code = main(
        [
            "fedreg",
            "--environment=TU",
            f"--issuer-uri={_ISSUER}",
            "--member-id=FDexample0112TU",
            "--contact-email=a@example.com",
            f"--jwks={jwks_path}",
        ]
    )

    assert code == 0
    captured = capsys.readouterr()
    assert "<registrierungtifoederation>" in captured.out
    assert "RP_register.xsd" in captured.err  # the mandatory validate-before-submitting warning


def test_fedreg_validation_failure_is_reported_on_stderr_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_dir = tmp_path / "keys"
    main(["keygen", f"--issuer-uri={_ISSUER}", f"--out-dir={out_dir}"])
    jwks_path = out_dir / f"es_sig_{_SLUG}_jwks.json"
    capsys.readouterr()

    code = main(
        [
            "fedreg",
            "--environment=TU",
            "--issuer-uri=http://gid.example.com",  # not https -- must fail validation
            "--member-id=FDexample0112TU",
            "--contact-email=a@example.com",
            f"--jwks={jwks_path}",
        ]
    )

    assert code != 0
    captured = capsys.readouterr()
    assert captured.err.startswith("error:")
    assert "Traceback" not in captured.err

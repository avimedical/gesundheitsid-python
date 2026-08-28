"""__version__ must track the distribution, not a hand-edited literal."""

import tomllib
from importlib.metadata import version
from pathlib import Path

import gesundheitsid

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_version_matches_the_installed_distribution() -> None:
    assert gesundheitsid.__version__ == version("gesundheitsid")


def test_version_matches_pyproject() -> None:
    """The drift this replaced: a literal in __init__.py said 0.1.0 while pyproject said 0.3.0,
    so `python -c "import gesundheitsid; print(gesundheitsid.__version__)"` in a running pod
    reported a version that had not been deployed for two releases."""
    declared = tomllib.loads(_PYPROJECT.read_text())["project"]["version"]

    assert gesundheitsid.__version__ == declared

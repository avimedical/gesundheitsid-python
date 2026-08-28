"""Framework-agnostic OpenID Federation relying party for Germany's GesundheitsID."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Read from installed metadata rather than a literal: a hand-maintained constant here sat
    # at 0.1.0 through two releases, so a deployed pod reported a version it was not running.
    __version__ = version("gesundheitsid")
except PackageNotFoundError:  # imported straight from a source tree, never installed
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]

"""Entry point for `gesundheitsid-cli`: dispatches to `keygen` / `fedreg`, converting any
`GesundheitsIdError` into a one-line stderr message and a non-zero exit code instead of a
traceback -- this is a CLI, and its users are not expected to read Python stack traces.
"""

from __future__ import annotations

import argparse
import sys

from gesundheitsid.errors import GesundheitsIdError
from gesundheitsid_cli import fedreg, keygen

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gesundheitsid-cli",
        description="Key generation and gematik Federation Master registration for a GesundheitsID relying party.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    keygen.add_subparser(subparsers)
    fedreg.add_subparser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GesundheitsIdError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

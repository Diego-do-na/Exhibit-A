"""Implementation of the ``verify`` CLI subcommand (extension module).

``exhibit-a verify <package>`` re-checks a proof bundle offline: the
manifest must be present and well formed, every listed file must hash to
its recorded digest, no unlisted file may be present, and the manifest
signature must verify under the attestation key. Any single-byte change in
the bundle fails at least one check.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from exhibit_a.attest import resolve_key, verify_package


def _key_from_args(args: argparse.Namespace) -> bytes | None:
    if getattr(args, "key", None):
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            print("verify: --key is not hex", file=sys.stderr)
            raise SystemExit(2) from None
        if len(key) < 16:
            print("verify: --key is too short", file=sys.stderr)
            raise SystemExit(2)
        return key
    if getattr(args, "key_file", None):
        from exhibit_a.attest import load_key_file

        try:
            return load_key_file(Path(args.key_file))
        except ValueError as exc:
            print(f"verify: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
    try:
        return resolve_key()
    except ValueError as exc:
        print(f"verify: {exc}", file=sys.stderr)
        raise SystemExit(2)


def cmd_verify(args: argparse.Namespace) -> int:
    """Check every file hash and the manifest signature; exit 0 only if all pass."""
    try:
        key = _key_from_args(args)
    except SystemExit as exit_:
        return int(exit_.code or 0)
    report = verify_package(Path(args.package), key)
    for check in report.checks:
        status = "PASS" if check.passed else "FAIL"
        suffix = f": {check.detail}" if check.detail and not check.passed else ""
        print(f"{status} {check.name}{suffix}")
    return 0 if report.passed else 1


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``verify`` subcommand to the CLI."""
    parser = sub.add_parser(
        "verify",
        help="Check a proof bundle offline: file hashes and manifest signature.",
    )
    parser.add_argument("package", help="Proof-bundle directory to check.")
    parser.add_argument(
        "--key",
        default=None,
        help="Attestation key as hex (overrides EXHIBIT_A_ATTEST_KEY).",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        metavar="FILE",
        help="File holding the attestation key as hex.",
    )
    parser.set_defaults(func=cmd_verify)

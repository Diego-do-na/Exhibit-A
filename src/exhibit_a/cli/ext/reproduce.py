"""Implementation of the ``reproduce`` CLI subcommand (extension module).

``exhibit-a reproduce <package> --repo <clone>`` replays a proof bundle
with no model call at all: it runs the bundled exploit test in the
isolated, resource-limited sandbox against the vulnerable tree (which must
be proven again for the same effect through the same entry point) and
against the tree with ``fix.patch`` applied (which must not be proven).
Exit codes: 0 reproduced, 10 not reproduced, 20 incomplete (the bundle is
unusable or the sandbox could not run).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from exhibit_a.attest import resolve_key, verify_package

REPRODUCED = 0
NOT_REPRODUCED = 10
INCOMPLETE = 20


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _apply_patch(tree: Path, patch_file: Path) -> str:
    """Apply a unified diff to ``tree``; return the tool used or raise."""
    patch_text = patch_file.read_text(encoding="utf-8")
    if not patch_text.strip():
        raise ValueError("fix.patch is empty")
    if shutil.which("git") is not None:
        check = subprocess.run(
            ["git", "apply", "--check", "-p1", str(patch_file)],
            cwd=tree, capture_output=True, timeout=60,
        )
        if check.returncode == 0:
            applied = subprocess.run(
                ["git", "apply", "-p1", str(patch_file)],
                cwd=tree, capture_output=True, timeout=60,
            )
            if applied.returncode == 0:
                return "git apply"
            raise ValueError(
                "git apply failed: "
                + applied.stderr.decode("utf-8", "replace")[-500:]
            )
    if shutil.which("patch") is not None:
        applied = subprocess.run(
            ["patch", "-p1", "-s", "-i", str(patch_file)],
            cwd=tree, capture_output=True, timeout=60,
        )
        if applied.returncode == 0:
            return "patch -p1"
        raise ValueError(
            "patch failed: " + applied.stderr.decode("utf-8", "replace")[-500:]
        )
    raise ValueError("neither git nor patch is available to apply fix.patch")


def cmd_reproduce(args: argparse.Namespace) -> int:
    """Re-run a bundle's proof against a vulnerable tree, with no model call."""
    from exhibit_a.loop.pipeline import classify
    from exhibit_a.loop.runner import SandboxRunner

    package = Path(args.package)
    manifest_path = package / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"reproduce: cannot read manifest: {exc}", file=sys.stderr)
        print("INCOMPLETE: bundle manifest is unreadable")
        return INCOMPLETE
    print(f"PACKAGE {package}")

    key = None
    if getattr(args, "key", None):
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            print("reproduce: --key is not hex", file=sys.stderr)
            return 2
    elif getattr(args, "key_file", None):
        from exhibit_a.attest import load_key_file

        try:
            key = load_key_file(Path(args.key_file))
        except ValueError as exc:
            print(f"reproduce: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            key = resolve_key()
        except ValueError as exc:
            print(f"reproduce: {exc}", file=sys.stderr)
            return 2
    report = verify_package(package, key)
    for check in report.checks:
        status = "PASS" if check.passed else "FAIL"
        suffix = f": {check.detail}" if check.detail and not check.passed else ""
        print(f"{status} {check.name}{suffix}")
    hash_ok = all(
        check.passed for check in report.checks if not check.name == "signature"
    ) and any(report.checks)
    signature_check = next(
        (check for check in report.checks if check.name == "signature"), None
    )
    if not hash_ok:
        print("INCOMPLETE: bundle files do not match the manifest")
        return INCOMPLETE
    if signature_check is not None and not signature_check.passed:
        if key is None:
            print("WARNING no attestation key available: continuing on file hashes; "
                  "the sandbox re-run below is the proof")
        else:
            print("INCOMPLETE: manifest signature does not verify")
            return INCOMPLETE

    effect = manifest.get("effect")
    entry_point = manifest.get("entry_point")
    if effect not in ("canary_read", "canary_write", "canary_exec"):
        print(f"INCOMPLETE: manifest names an unknown effect: {effect!r}")
        return INCOMPLETE
    if not isinstance(entry_point, str) or not entry_point:
        print("INCOMPLETE: manifest names no entry point")
        return INCOMPLETE
    requirements = manifest.get("requirements") or []
    if not isinstance(requirements, list) or any(
        not isinstance(item, str) for item in requirements
    ):
        print("INCOMPLETE: manifest requirements are malformed")
        return INCOMPLETE
    exploit_src = package / "test_exploit.py"
    patch_file = package / "fix.patch"
    if not exploit_src.is_file() or not patch_file.is_file():
        print("INCOMPLETE: bundle is missing test_exploit.py or fix.patch")
        return INCOMPLETE

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"reproduce: repository does not exist: {repo}", file=sys.stderr)
        return 2
    if not _docker_ready():
        print("INCOMPLETE: Docker is not available, the sandbox could not run")
        return INCOMPLETE

    print("MODEL CALLS 0")
    runner = SandboxRunner(requirements=tuple(requirements))
    timeout = float(args.timeout)
    try:
        with tempfile.TemporaryDirectory(prefix="exhibit_a_reproduce_") as tmp:
            vuln = Path(tmp) / "vulnerable"
            shutil.copytree(repo, vuln)
            try:
                judgement = runner.run_exploit(
                    vuln, exploit_src, {entry_point}, timeout=timeout, effect=effect,
                )
            except OSError as exc:
                print(f"INCOMPLETE: the sandbox could not run the exploit: {exc}")
                return INCOMPLETE
            verdict = classify(judgement)
            print(
                f"VULNERABLE outcome={judgement.test_outcome} "
                f"effect={'yes' if judgement.observed_effect else 'no'} "
                f"provenance={'ok' if judgement.provenance_ok else 'no'} "
                f"verdict={verdict.value}"
            )
            if verdict.value != "proven":
                print(f"NOT REPRODUCED: exploit does not prove {effect} "
                      f"via {entry_point} ({judgement.reason})")
                return NOT_REPRODUCED
            fixed = Path(tmp) / "fixed"
            shutil.copytree(repo, fixed)
            try:
                method = _apply_patch(fixed, patch_file)
            except (OSError, ValueError) as exc:
                print(f"INCOMPLETE: fix.patch does not apply: {exc}")
                return INCOMPLETE
            print(f"FIX APPLIED {method}")
            try:
                fixed_judgement = runner.run_exploit(
                    fixed, exploit_src, {entry_point}, timeout=timeout, effect=effect,
                )
            except OSError as exc:
                print(f"INCOMPLETE: the sandbox could not run the fixed tree: {exc}")
                return INCOMPLETE
            fixed_verdict = classify(fixed_judgement)
            print(
                f"FIXED outcome={fixed_judgement.test_outcome} "
                f"verdict={fixed_verdict.value}"
            )
            if fixed_verdict.value == "proven":
                print("NOT REPRODUCED: the exploit still proves the flaw after fix.patch")
                return NOT_REPRODUCED
    except OSError as exc:
        print(f"INCOMPLETE: cannot stage the repository copy: {exc}")
        return INCOMPLETE
    print(f"REPRODUCED: {effect} via {entry_point} proven on the vulnerable tree, "
          "not proven with fix.patch applied, with no model call")
    return REPRODUCED


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``reproduce`` subcommand to the CLI."""
    parser = sub.add_parser(
        "reproduce",
        help="Re-run a proof bundle in the sandbox with no model call.",
    )
    parser.add_argument("package", help="Proof-bundle directory to reproduce.")
    parser.add_argument(
        "--repo",
        required=True,
        help="Vulnerable source tree to replay the proof against.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Seconds per sandbox run (default: 120).",
    )
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
    parser.set_defaults(func=cmd_reproduce)

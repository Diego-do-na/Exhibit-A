"""Build, sign, write and check proof-bundle manifests."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import exhibit_a

MANIFEST_NAME = "manifest.json"
SCHEMA_VERSION = 1

#: Files the manifest covers when present. Unexpected top-level files fail
#: verification: the bundle must be exactly what the manifest describes.
EXPECTED_FILES = ("test_exploit.py", "fix.patch", "evidence.json", "verdict.json")


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file, streamed so large files stay small in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def engine_version() -> str:
    """The running Exhibit A version."""
    return exhibit_a.__version__


def engine_commit() -> str:
    """The engine's git commit, or ``"unknown"`` outside a git checkout."""
    root = Path(exhibit_a.__file__).resolve().parents[2]
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    commit = proc.stdout.decode("ascii", "replace").strip()
    return commit if commit else "unknown"


def _canonical(body: dict[str, Any]) -> bytes:
    """Canonical bytes of a manifest body: same JSON shape as oracle events."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _signature_bytes(body: dict[str, Any]) -> bytes:
    """What a manifest signature covers: a domain tag plus the canonical body.

    The tag keeps manifest signatures distinct from oracle-event signatures
    (those cover ``seq`` plus the body, see ``_signed_bytes``); the HMAC
    construction itself is shared.
    """
    return b"manifest-v1\n" + _canonical(body)


def sign_manifest(body: dict[str, Any], key: bytes) -> str:
    """Hex HMAC-SHA256 over the canonical manifest body."""
    return hmac.new(key, _signature_bytes(body), hashlib.sha256).hexdigest()


def _check_signature(body: dict[str, Any], signature: str, key: bytes) -> bool:
    if not isinstance(signature, str) or not signature:
        return False
    try:
        expected = hmac.new(key, _signature_bytes(body), hashlib.sha256).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, signature)


ManifestData = dict[str, Any]


def build_manifest(
    files: dict[str, str],
    *,
    exhibit_a_version: str,
    exhibit_a_commit: str,
    case_id: str,
    repo_commit: str | None = None,
    diff_hash: str | None = None,
    effect: str,
    entry_point: str,
    oracle_verdict: dict[str, Any],
    ledger_events: list[dict[str, Any]],
    requirements: list[str] | tuple[str, ...] = (),
) -> ManifestData:
    """Assemble the unsigned manifest body over file digests and proof metadata."""
    return {
        "schema_version": SCHEMA_VERSION,
        "files": dict(sorted(files.items())),
        "exhibit_a_version": exhibit_a_version,
        "exhibit_a_commit": exhibit_a_commit,
        "case_id": case_id,
        "repo_commit": repo_commit,
        "diff_hash": diff_hash,
        "effect": effect,
        "entry_point": entry_point,
        "oracle_verdict": oracle_verdict,
        "ledger_events": list(ledger_events),
        "requirements": list(requirements),
    }


def _package_files(package_dir: Path) -> dict[str, str]:
    """SHA-256 of every top-level file except the manifest itself."""
    digests: dict[str, str] = {}
    for child in sorted(package_dir.iterdir(), key=lambda p: p.name):
        if child.name == MANIFEST_NAME or not child.is_file() or child.is_symlink():
            continue
        digests[child.name] = sha256_file(child)
    return digests


def write_manifest(
    package_dir: Path,
    key: bytes,
    *,
    case_id: str,
    repo_commit: str | None = None,
    diff_hash: str | None = None,
    effect: str,
    entry_point: str,
    oracle_verdict: dict[str, Any],
    ledger_events: list[dict[str, Any]],
    requirements: list[str] | tuple[str, ...] = (),
) -> Path:
    """Hash the package, sign the manifest body, write ``manifest.json``."""
    package_dir = Path(package_dir)
    body = build_manifest(
        _package_files(package_dir),
        exhibit_a_version=engine_version(),
        exhibit_a_commit=engine_commit(),
        case_id=case_id,
        repo_commit=repo_commit,
        diff_hash=diff_hash,
        effect=effect,
        entry_point=entry_point,
        oracle_verdict=oracle_verdict,
        ledger_events=ledger_events,
        requirements=requirements,
    )
    manifest = dict(body)
    manifest["signature"] = sign_manifest(body, key)
    path = package_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


@dataclass(frozen=True)
class ManifestCheck:
    """One offline check and whether it passed."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class VerifyReport:
    """The outcome of checking a package: every check and the overall call."""

    checks: tuple[ManifestCheck, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        """True only when every check passed."""
        return bool(self.checks) and all(check.passed for check in self.checks)


_REQUIRED_BODY_KEYS = (
    "schema_version",
    "files",
    "exhibit_a_version",
    "exhibit_a_commit",
    "case_id",
    "effect",
    "entry_point",
    "oracle_verdict",
    "ledger_events",
)


def verify_package(package_dir: Path, key: bytes | None) -> VerifyReport:
    """Check a package offline: manifest shape, file hashes, then the signature.

    A missing or unreadable manifest fails closed. Hash checks run before
    the signature so a tampered file is reported as such even when the
    signature would also fail.
    """
    package_dir = Path(package_dir)
    checks: list[ManifestCheck] = []
    manifest_path = package_dir / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return VerifyReport((ManifestCheck("manifest readable", False, str(exc)),))
    checks.append(ManifestCheck("manifest readable", True))
    if not isinstance(manifest, dict):
        return VerifyReport(
            (*checks, ManifestCheck("manifest schema", False, "manifest is not a JSON object"))
        )
    missing = [name for name in _REQUIRED_BODY_KEYS if name not in manifest]
    if missing:
        checks.append(
            ManifestCheck("manifest schema", False, f"missing keys: {', '.join(missing)}")
        )
        return VerifyReport(tuple(checks))
    if manifest.get("schema_version") != SCHEMA_VERSION:
        checks.append(
            ManifestCheck(
                "manifest schema", False,
                f"unsupported schema_version: {manifest.get('schema_version')!r}",
            )
        )
        return VerifyReport(tuple(checks))
    if not isinstance(manifest.get("files"), dict) or not manifest["files"]:
        checks.append(ManifestCheck("manifest schema", False, "files map is empty"))
        return VerifyReport(tuple(checks))
    checks.append(ManifestCheck("manifest schema", True))

    listed = manifest["files"]
    for name in sorted(listed):
        target = package_dir / name
        if not target.is_file() or target.is_symlink():
            checks.append(ManifestCheck(f"hash {name}", False, "file is missing"))
            continue
        actual = sha256_file(target)
        if not hmac.compare_digest(actual, str(listed[name])):
            checks.append(
                ManifestCheck(f"hash {name}", False, "digest does not match the manifest")
            )
        else:
            checks.append(ManifestCheck(f"hash {name}", True))
    actual_files = {
        child.name
        for child in package_dir.iterdir()
        if child.is_file() and not child.is_symlink() and child.name != MANIFEST_NAME
    }
    unexpected = sorted(actual_files - set(listed))
    if unexpected:
        checks.append(
            ManifestCheck(
                "no unexpected files", False,
                f"files not listed in the manifest: {', '.join(unexpected)}",
            )
        )
    else:
        checks.append(ManifestCheck("no unexpected files", True))

    signature = manifest.get("signature", "")
    body = {name: manifest[name] for name in manifest if name != "signature"}
    if key is None:
        checks.append(ManifestCheck("signature", False, "no attestation key available"))
    elif _check_signature(body, signature, key):
        checks.append(ManifestCheck("signature", True))
    else:
        checks.append(ManifestCheck("signature", False, "signature does not verify"))
    return VerifyReport(tuple(checks))

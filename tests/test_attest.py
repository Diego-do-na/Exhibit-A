"""Tests for proof-bundle manifests: hashes, signatures, and the packaging hook."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exhibit_a import attest
from exhibit_a.attest import keys as key_module

TEST_KEY = bytes.fromhex("0f" * 32)
WRONG_KEY = bytes.fromhex("f0" * 32)


def _package_dir(root: Path) -> Path:
    package = root / "pkg"
    package.mkdir()
    (package / "test_exploit.py").write_text("assert True\n", encoding="utf-8")
    (package / "fix.patch").write_text("--- a/app.py\n+++ b/app.py\n@@\n-x\n+y\n", encoding="utf-8")
    (package / "verdict.json").write_text(
        json.dumps({"suspicion_id": "S-1", "verdict": "proven"}), encoding="utf-8"
    )
    (package / "evidence.json").write_text(json.dumps({"reason": "canary read"}), encoding="utf-8")
    return package


def write_signed(package: Path, key: bytes = TEST_KEY) -> Path:
    """Write a manifest over ``package`` with fixed proof metadata."""
    return attest.write_manifest(
        package,
        key,
        case_id="case-1",
        effect="canary_read",
        entry_point="App.handle_request",
        oracle_verdict={"verdict": "proven"},
        ledger_events=[{"index": 3, "type": "verdict"}],
    )


def test_roundtrip_passes(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    report = attest.verify_package(package, TEST_KEY)
    assert report.passed
    assert all(check.passed for check in report.checks)
    assert {check.name for check in report.checks} >= {
        "manifest readable",
        "manifest schema",
        "hash test_exploit.py",
        "no unexpected files",
        "signature",
    }


def test_tampered_file_fails(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    with (package / "test_exploit.py").open("ab") as handle:
        handle.write(b" ")
    report = attest.verify_package(package, TEST_KEY)
    assert not report.passed
    by_name = {check.name: check for check in report.checks}
    assert not by_name["hash test_exploit.py"].passed
    assert by_name["hash fix.patch"].passed


def test_tampered_manifest_fails(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    manifest["effect"] = "canary_write"  # files untouched: only the signature can catch this
    (package / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    report = attest.verify_package(package, TEST_KEY)
    assert not report.passed
    by_name = {check.name: check for check in report.checks}
    assert all(check.passed for name, check in by_name.items() if name.startswith("hash "))
    assert not by_name["signature"].passed


def test_wrong_key_fails_signature_only(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    report = attest.verify_package(package, WRONG_KEY)
    assert not report.passed
    by_name = {check.name: check for check in report.checks}
    assert all(check.passed for name, check in by_name.items() if name.startswith("hash "))
    assert not by_name["signature"].passed


def test_missing_key_fails_signature(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    report = attest.verify_package(package, None)
    assert not report.passed
    assert not next(c for c in report.checks if c.name == "signature").passed


def test_missing_file_fails(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    (package / "fix.patch").unlink()
    report = attest.verify_package(package, TEST_KEY)
    assert not report.passed
    assert not next(c for c in report.checks if c.name == "hash fix.patch").passed


def test_extra_file_fails(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    (package / "notes.txt").write_text("extra", encoding="utf-8")
    report = attest.verify_package(package, TEST_KEY)
    assert not report.passed
    assert not next(c for c in report.checks if c.name == "no unexpected files").passed


def test_missing_manifest_fails(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    report = attest.verify_package(package, TEST_KEY)
    assert not report.passed


def test_manifest_records_engine_and_proof_metadata(tmp_path: Path) -> None:
    package = _package_dir(tmp_path)
    write_signed(package)
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert set(manifest["files"]) == {
        "test_exploit.py",
        "fix.patch",
        "evidence.json",
        "verdict.json",
    }
    assert manifest["exhibit_a_version"] == attest.engine_version()
    assert manifest["exhibit_a_commit"]
    assert manifest["case_id"] == "case-1"
    assert manifest["effect"] == "canary_read"
    assert manifest["entry_point"] == "App.handle_request"
    assert manifest["oracle_verdict"] == {"verdict": "proven"}
    assert manifest["ledger_events"] == [{"index": 3, "type": "verdict"}]
    assert manifest["signature"]


def test_resolve_key_prefers_explicit_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(key_module.KEY_ENV_VAR, WRONG_KEY.hex())
    assert attest.resolve_key(TEST_KEY) == TEST_KEY
    assert attest.resolve_key() == WRONG_KEY


def test_resolve_key_reads_generated_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(key_module.KEY_ENV_VAR, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    created = attest.resolve_key(create=True)
    assert created is not None and len(created) == 32
    assert attest.default_key_path().is_file()
    assert attest.resolve_key() == created


def test_short_keys_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError):
        attest.resolve_key(b"short")
    monkeypatch.setenv(key_module.KEY_ENV_VAR, "0f0f")
    with pytest.raises(ValueError):
        attest.resolve_key()


def test_packaging_hook_writes_a_verifying_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loop's PACKAGE step writes manifest.json, signed and hash-clean."""
    from test_loop import Scripted, make_loop

    monkeypatch.setenv(key_module.KEY_ENV_VAR, TEST_KEY.hex())
    root = tmp_path / "hooked"
    root.mkdir()
    counter = root / "flaky.count"
    loop, _ = make_loop(root, root / "replay.jsonl", Scripted(counter))
    result = loop.run("app.py")
    proven = next(r for r in result.results if r.suspicion.id == "S-PROVEN")
    assert proven.package_dir is not None
    manifest = json.loads((proven.package_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["case_id"] == "r1"
    assert manifest["effect"] == "canary_read"
    assert manifest["entry_point"]
    assert manifest["ledger_events"], "the manifest must cite supporting ledger events"
    assert {e["type"] for e in manifest["ledger_events"]} >= {"verdict"}
    assert attest.verify_package(proven.package_dir, TEST_KEY).passed

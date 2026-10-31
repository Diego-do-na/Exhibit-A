"""Tests for ``exhibit-a reproduce``: replaying a proof with no model call.

The two sandbox tests rebuild a proof bundle from the archive-extraction
corpus case (vulnerable tree, true exploit, fixed tree) and replay it:
the exploit must prove the write effect through the declared entry point
on the vulnerable tree and stop proving once the fix is applied. They need
Docker and are marked accordingly. The remaining tests need no Docker.
"""

from __future__ import annotations

import argparse
import difflib
import json
import shutil
from pathlib import Path

import pytest

from exhibit_a import attest
from exhibit_a.cli.ext.reproduce import cmd_reproduce

ROOT = Path(__file__).parents[1]
CASE = ROOT / "bench" / "corpus" / "archive-extraction-pathtraversal"
TEST_KEY = bytes.fromhex("0e" * 32)


def _unified_patch(before: Path, after: Path) -> str:
    old = before.read_text(encoding="utf-8").splitlines(keepends=True)
    new = after.read_text(encoding="utf-8").splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(old, new, fromfile="a/archive.py", tofile="b/archive.py")
    )


def make_package(root: Path, *, fixed_tree: str) -> tuple[Path, Path]:
    """Build a proof bundle from corpus materials, with no model call.

    Returns ``(package, vulnerable_tree)``: the exploit is the case's own
    true absolute-path exploit and the fix is the tree diff of ``fixed_tree``
    (``fixed`` stops the exploit, ``fixed_incomplete`` does not).
    """
    vuln = root / "vulnerable"
    shutil.copytree(CASE / "vulnerable", vuln)
    package = root / "package"
    package.mkdir()
    shutil.copyfile(CASE / "exploits" / "exploit_true_absolute.py", package / "test_exploit.py")
    (package / "fix.patch").write_text(
        _unified_patch(CASE / "vulnerable" / "archive.py", CASE / fixed_tree / "archive.py"),
        encoding="utf-8",
    )
    (package / "verdict.json").write_text(
        json.dumps({"suspicion_id": "S-ARCHIVE", "verdict": "proven"}), encoding="utf-8"
    )
    (package / "evidence.json").write_text(
        json.dumps({"reason": "archive member escaped the destination"}), encoding="utf-8"
    )
    attest.write_manifest(
        package,
        TEST_KEY,
        case_id="archive-extraction-pathtraversal",
        effect="canary_write",
        entry_point="App.handle_request",
        oracle_verdict={"verdict": "proven", "effect": "canary_write"},
        ledger_events=[{"index": 5, "type": "verdict"}],
    )
    assert attest.verify_package(package, TEST_KEY).passed
    return package, vuln


def run_reproduce(package: Path, repo: Path, capsys, **kwargs) -> int:
    args = argparse.Namespace(
        package=str(package),
        repo=str(repo),
        timeout=kwargs.get("timeout", 180.0),
        key=TEST_KEY.hex(),
        key_file=None,
    )
    code = cmd_reproduce(args)
    return code, capsys.readouterr().out


@pytest.mark.docker
def test_reproduce_proves_again_with_no_model_call(tmp_path: Path, capsys) -> None:
    package, vuln = make_package(tmp_path, fixed_tree="fixed")
    code, out = run_reproduce(package, vuln, capsys)
    assert code == 0, out
    assert "MODEL CALLS 0" in out
    assert "VULNERABLE" in out and "verdict=proven" in out
    assert "FIXED" in out
    assert "REPRODUCED" in out


@pytest.mark.docker
def test_reproduce_reports_not_reproduced_when_the_fix_fails(tmp_path: Path, capsys) -> None:
    package, vuln = make_package(tmp_path, fixed_tree="fixed_incomplete")
    code, out = run_reproduce(package, vuln, capsys)
    assert code == 10, out
    assert "NOT REPRODUCED" in out


def test_reproduce_without_a_manifest_is_incomplete(tmp_path: Path, capsys) -> None:
    package = tmp_path / "package"
    package.mkdir()
    args = argparse.Namespace(
        package=str(package), repo=str(tmp_path), timeout=60.0, key=None, key_file=None,
    )
    assert cmd_reproduce(args) == 20
    assert "INCOMPLETE" in capsys.readouterr().out


def test_reproduce_with_an_unknown_effect_is_incomplete(tmp_path: Path, capsys) -> None:
    package = tmp_path / "package"
    package.mkdir()
    (package / "test_exploit.py").write_text("assert True\n", encoding="utf-8")
    body = attest.build_manifest(
        {"test_exploit.py": attest.sha256_file(package / "test_exploit.py")},
        exhibit_a_version=attest.engine_version(),
        exhibit_a_commit=attest.engine_commit(),
        case_id="case-1",
        effect="not_an_effect",
        entry_point="App.handle_request",
        oracle_verdict={},
        ledger_events=[],
    )
    manifest = dict(body)
    manifest["signature"] = attest.sign_manifest(body, TEST_KEY)
    (package / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    args = argparse.Namespace(
        package=str(package), repo=str(tmp_path), timeout=60.0,
        key=TEST_KEY.hex(), key_file=None,
    )
    assert cmd_reproduce(args) == 20
    assert "unknown effect" in capsys.readouterr().out


def test_reproduce_without_docker_is_incomplete(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, _ = make_package(tmp_path, fixed_tree="fixed")
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
    args = argparse.Namespace(
        package=str(package), repo=str(tmp_path), timeout=60.0,
        key=TEST_KEY.hex(), key_file=None,
    )
    assert cmd_reproduce(args) == 20
    assert "Docker is not available" in capsys.readouterr().out


def test_reproduce_without_a_repo_is_a_usage_error(tmp_path: Path, capsys) -> None:
    package, _ = make_package(tmp_path, fixed_tree="fixed")
    args = argparse.Namespace(
        package=str(package), repo=str(tmp_path / "missing"), timeout=60.0,
        key=TEST_KEY.hex(), key_file=None,
    )
    assert cmd_reproduce(args) == 2

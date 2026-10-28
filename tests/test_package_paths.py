"""A packaged proof must be portable: no absolute host paths, canonical JSON keys."""

import json
from pathlib import Path

from test_loop import Scripted, make_loop


def package(tmp_path):
    loop, _ = make_loop(tmp_path, tmp_path / "replay.jsonl", Scripted(tmp_path / "flaky.count"))
    result = loop.run("app.py")
    proven = next(r for r in result.results if r.suspicion.id == "S-PROVEN")
    return loop, proven.package_dir


def test_package_files_leak_no_host_paths(tmp_path):
    _, pkg = package(tmp_path)
    for name in ("verdict.json", "evidence.json", "fix.patch"):
        text = (pkg / name).read_text()
        assert str(tmp_path) not in text, name
        assert str(Path.home()) not in text, name
        assert "/Users/" not in text, name


def test_package_paths_are_relative_to_the_package_dir(tmp_path):
    _, pkg = package(tmp_path)
    verdict = json.loads((pkg / "verdict.json").read_text())
    assert verdict["evidence"]["test_path"] == "test_exploit.py"
    assert verdict["fix"]["patch_path"] == "fix.patch"
    for key in (verdict["evidence"]["test_path"], verdict["fix"]["patch_path"]):
        assert (pkg / key).is_file()


def test_evidence_uses_the_canonical_class_key(tmp_path):
    _, pkg = package(tmp_path)
    suspicion = json.loads((pkg / "evidence.json").read_text())["suspicion"]
    assert "class" in suspicion
    assert "vuln_class" not in suspicion

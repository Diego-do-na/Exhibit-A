import subprocess
from pathlib import Path

import pytest

from exhibit_a.cli.run import parse_name_status
from exhibit_a.ci.summary import build_result
from exhibit_a.ledger import Ledger


def test_parse_name_status_handles_rename_and_delete() -> None:
    entries = parse_name_status(
        b"R100\0old.py\0new.py\0D\0gone.py\0M\0plain.py\0"
    )
    assert [(e.status, e.path, e.old_path) for e in entries] == [
        ("R", "new.py", "old.py"),
        ("D", "gone.py", None),
        ("M", "plain.py", None),
    ]


@pytest.mark.parametrize("raw", [b"A\0../escape.py\0", b"A\0/absolute.py\0"])
def test_parse_name_status_preserves_adversarial_names(raw: bytes) -> None:
    entry = parse_name_status(raw)[0]
    assert entry.path in {"../escape.py", "/absolute.py"}


def test_parse_name_status_rejects_huge_diff() -> None:
    with pytest.raises(ValueError, match="too large"):
        parse_name_status(b"A\0x.py\0", max_bytes=2)


def test_result_from_not_applicable_ledger_is_renderable(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    from exhibit_a.schemas import Event, EventType

    ledger.append(Event(
        ts="2026-10-29T00:00:00Z",
        run_id="pr-head",
        type=EventType.SCAN_DONE,
        payload={"status": "not_applicable"},
    ))
    result = build_result(ledger.read_all(), run_id="pr-head", engine_exit=0)
    assert result["status"] == "completed"
    assert result["surface_ran"] is True
    assert result["proven"] == 0


def test_zero_python_diff_writes_ledger_and_result(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    (repo / "README.md").write_text("head\n", encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "head"], cwd=repo, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD^"], cwd=repo, text=True).strip()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

    from exhibit_a.cli import main

    assert main([
        "run", "--repo", str(repo), "--out", str(tmp_path / "out"),
        "--pr-diff", f"{base}..{head}", "--replay",
        "--recording", str(tmp_path / "recording.jsonl"),
    ]) == 0
    assert (tmp_path / "out" / "ledger.jsonl").is_file()
    assert (tmp_path / "out" / "result.json").is_file()

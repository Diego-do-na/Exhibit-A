"""Security regression tests for hostile fixer output."""

from pathlib import Path

import pytest

from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop
from exhibit_a.loop.pipeline import _MAX_FIX_FILE_BYTES, _MAX_FIX_FILES, _MAX_FIX_TOTAL_BYTES


def make_loop(tmp_path: Path) -> VerificationLoop:
    clone = tmp_path / "clone"
    clone.mkdir()
    return VerificationLoop(
        clone,
        tmp_path / "out",
        Ledger(tmp_path / "ledger.jsonl"),
        Roles(None, None, None, None),
        "test.py",
    )


def test_oversized_fix_content_is_rejected_before_copy(tmp_path):
    loop = make_loop(tmp_path)

    with pytest.raises(ValueError, match="fix content exceeds limit"):
        loop._apply_fix(
            [{"path": "app.py", "content": "x" * (_MAX_FIX_FILE_BYTES + 1)}],
            tmp_path / "fixed",
        )

    assert not (tmp_path / "fixed").exists()


def test_many_fix_files_are_rejected_before_copy(tmp_path):
    loop = make_loop(tmp_path)
    files = [{"path": f"file_{i}.py", "content": "pass"} for i in range(_MAX_FIX_FILES + 1)]

    with pytest.raises(ValueError, match="too many files"):
        loop._apply_fix(files, tmp_path / "fixed")

    assert not (tmp_path / "fixed").exists()


def test_total_fix_content_is_bounded(tmp_path):
    loop = make_loop(tmp_path)
    content = "x" * (_MAX_FIX_FILE_BYTES // 2)
    files = [
        {"path": f"file_{i}.py", "content": content}
        for i in range((_MAX_FIX_TOTAL_BYTES // len(content)) + 1)
    ]

    with pytest.raises(ValueError, match="total limit"):
        loop._apply_fix(files, tmp_path / "fixed")


def test_fix_path_through_clone_symlink_is_rejected(tmp_path):
    loop = make_loop(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (loop.clone / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="traverses symlink"):
        loop._apply_fix(
            [{"path": "linked/escape.py", "content": "pwned"}],
            tmp_path / "fixed",
        )


def test_archive_path_trick_is_rejected(tmp_path):
    loop = make_loop(tmp_path)
    (loop.clone / "payload.zip").write_bytes(b"not a directory")

    with pytest.raises(ValueError, match="non-directory"):
        loop._apply_fix(
            [{"path": "payload.zip/evil.py", "content": "pwned"}],
            tmp_path / "fixed",
        )

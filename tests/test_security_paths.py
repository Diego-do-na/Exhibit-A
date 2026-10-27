"""Security tests for fixer output path-escape prevention.

Proves that a malicious or compromised fixer role output cannot write outside the clone:
- Absolute paths (e.g. /etc/passwd, /tmp/evil)
- Directory traversal / dot-segment escapes (e.g. ../outside, a/../../outside)
- Symlink targets pointing outside the clone (file symlinks, dir symlinks, relative symlinks, chained symlinks)
- Mixed proposals (valid file + escaping file)
- Full verification loop rejection and ledger event emission
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop
from exhibit_a.loop.pipeline import SuspicionResult
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.schemas import Evidence, EventType, Suspicion, Verdict, VerdictValue


def _make_loop(tmp_path: Path, clone_files: dict[str, str] | None = None) -> VerificationLoop:
    """Helper to instantiate a VerificationLoop with a minimal clone."""
    clone = tmp_path / "clone"
    clone.mkdir(parents=True, exist_ok=True)
    if clone_files:
        for rel_path, content in clone_files.items():
            dest = clone / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
    else:
        (clone / "app.py").write_text("def run():\n    return 'safe'\n", encoding="utf-8")

    ledger = Ledger(tmp_path / "ledger.jsonl")
    roles = Roles(
        adversary=ModelRole(Role.ADVERSARY, ReplayProvider(tmp_path / "replay.jsonl")),
        test_writer=ModelRole(Role.TEST_WRITER, ReplayProvider(tmp_path / "replay.jsonl")),
        fixer=ModelRole(Role.FIXER, ReplayProvider(tmp_path / "replay.jsonl")),
        defender=ModelRole(Role.DEFENDER, ReplayProvider(tmp_path / "replay.jsonl")),
    )
    return VerificationLoop(
        clone_path=clone,
        out_dir=tmp_path / "out",
        ledger=ledger,
        roles=roles,
        baseline_test="test_baseline.py",
    )


class TestAbsolutePaths:
    """Verify absolute paths in fixer output are rejected and cannot write outside clone."""

    @pytest.mark.parametrize(
        "escape_path",
        [
            "/etc/passwd",
            "/tmp/evil_exhibit_a_test.py",
            "//etc/shadow",
            "/var/tmp/malicious_test.py",
        ],
    )
    def test_absolute_path_is_rejected(self, tmp_path: Path, escape_path: str) -> None:
        loop = _make_loop(tmp_path)
        fixed = tmp_path / "fixed"

        canary = tmp_path / "canary.txt"
        canary.write_text("original-content", encoding="utf-8")

        # Even if the target path points to our canary outside the clone
        test_target = str(canary) if escape_path == "/tmp/evil_exhibit_a_test.py" else escape_path

        with pytest.raises(ValueError, match="(invalid fix path|escapes the clone)"):
            loop._apply_fix([{"path": test_target, "content": "malicious-write"}], fixed)

        assert canary.read_text(encoding="utf-8") == "original-content"
        assert not fixed.exists()


class TestRelativeTraversalEscapes:
    """Verify ../ dot-segment traversal escapes are rejected."""

    @pytest.mark.parametrize(
        "escape_path",
        [
            "..",
            "../canary.txt",
            "../../canary.txt",
            "subdir/../../canary.txt",
            "a/b/c/../../../../canary.txt",
            "foo/bar/../../../canary.txt",
        ],
    )
    def test_dot_segment_escape_is_rejected(self, tmp_path: Path, escape_path: str) -> None:
        loop = _make_loop(tmp_path)
        fixed = tmp_path / "fixed"

        canary = tmp_path / "canary.txt"
        canary.write_text("original-content", encoding="utf-8")

        with pytest.raises(ValueError, match="(invalid fix path|escapes the clone)"):
            loop._apply_fix([{"path": escape_path, "content": "malicious-write"}], fixed)

        assert canary.read_text(encoding="utf-8") == "original-content"
        assert not fixed.exists()


class TestSymlinkEscapes:
    """Verify existing symlinks pointing outside the clone cannot be used to write outside."""

    def test_symlink_file_pointing_outside_is_rejected(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "victim.txt"
        victim.write_text("safe-victim", encoding="utf-8")

        loop = _make_loop(tmp_path)
        (loop.clone / "link_to_victim").symlink_to(victim)

        fixed = tmp_path / "fixed"
        with pytest.raises(ValueError, match="escapes the clone"):
            loop._apply_fix([{"path": "link_to_victim", "content": "pwned"}], fixed)

        assert victim.read_text(encoding="utf-8") == "safe-victim"

    def test_symlink_dir_pointing_outside_is_rejected(self, tmp_path: Path) -> None:
        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()
        victim_in_dir = outside_dir / "target.py"
        victim_in_dir.write_text("safe-target", encoding="utf-8")

        loop = _make_loop(tmp_path)
        (loop.clone / "link_dir").symlink_to(outside_dir, target_is_directory=True)

        fixed = tmp_path / "fixed"
        with pytest.raises(ValueError, match="traverses symlink"):
            loop._apply_fix([{"path": "link_dir/target.py", "content": "pwned"}], fixed)

        assert victim_in_dir.read_text(encoding="utf-8") == "safe-target"

    def test_relative_symlink_pointing_outside_is_rejected(self, tmp_path: Path) -> None:
        outside_file = tmp_path / "outside_parent.txt"
        outside_file.write_text("untouched", encoding="utf-8")

        loop = _make_loop(tmp_path)
        # Relative symlink inside clone that resolves up to outside
        (loop.clone / "rel_link").symlink_to(Path("..") / "outside_parent.txt")

        fixed = tmp_path / "fixed"
        with pytest.raises(ValueError, match="escapes the clone"):
            loop._apply_fix([{"path": "rel_link", "content": "pwned"}], fixed)

        assert outside_file.read_text(encoding="utf-8") == "untouched"

    def test_chained_symlink_pointing_outside_is_rejected(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        target = outside / "deep_victim.txt"
        target.write_text("intact", encoding="utf-8")

        loop = _make_loop(tmp_path)
        (loop.clone / "hop2").symlink_to(target)
        (loop.clone / "hop1").symlink_to(loop.clone / "hop2")

        fixed = tmp_path / "fixed"
        with pytest.raises(ValueError, match="escapes the clone"):
            loop._apply_fix([{"path": "hop1", "content": "pwned"}], fixed)

        assert target.read_text(encoding="utf-8") == "intact"

    def test_internal_symlink_inside_clone_is_permitted(self, tmp_path: Path) -> None:
        loop = _make_loop(tmp_path, {"real.py": "x = 1\n"})
        (loop.clone / "internal_link.py").symlink_to(loop.clone / "real.py")

        fixed = tmp_path / "fixed"
        patch = loop._apply_fix([{"path": "internal_link.py", "content": "x = 2\n"}], fixed)

        assert bool(patch)
        assert (fixed / "internal_link.py").read_text(encoding="utf-8") == "x = 2\n"


class TestMixedAndMultiFileProposals:
    """Verify proposals containing both valid and malicious paths are completely aborted."""

    def test_batch_with_one_escaping_path_is_rejected_without_partial_apply(self, tmp_path: Path) -> None:
        loop = _make_loop(tmp_path, {"valid.py": "original = True\n"})
        fixed = tmp_path / "fixed"

        canary = tmp_path / "external_canary.txt"
        canary.write_text("clean", encoding="utf-8")

        files = [
            {"path": "valid.py", "content": "original = False\n"},
            {"path": "../external_canary.txt", "content": "dirty\n"},
        ]

        with pytest.raises(ValueError, match="(invalid fix path|escapes the clone)"):
            loop._apply_fix(files, fixed)

        # Neither the outside file nor the fixed directory contains the partial changes
        assert canary.read_text(encoding="utf-8") == "clean"
        assert not fixed.exists()

    def test_batch_with_symlink_escape_is_rejected_without_partial_apply(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "secret.txt"
        victim.write_text("original-secret", encoding="utf-8")

        loop = _make_loop(tmp_path, {"valid.py": "ok = True\n"})
        (loop.clone / "sym_link").symlink_to(victim)
        fixed = tmp_path / "fixed"

        files = [
            {"path": "valid.py", "content": "ok = False\n"},
            {"path": "sym_link", "content": "pwned-secret\n"},
        ]

        with pytest.raises(ValueError, match="escapes the clone"):
            loop._apply_fix(files, fixed)

        assert victim.read_text(encoding="utf-8") == "original-secret"


class TestLegitimateFixes:
    """Verify valid fix proposals inside the clone succeed and generate clean diffs."""

    def test_modifying_and_creating_nested_files_succeeds(self, tmp_path: Path) -> None:
        loop = _make_loop(tmp_path, {"app.py": "a = 1\n"})
        fixed = tmp_path / "fixed"

        files = [
            {"path": "app.py", "content": "a = 2\n"},
            {"path": "pkg/submodule/new.py", "content": "def helper(): return True\n"},
        ]

        patch = loop._apply_fix(files, fixed)

        assert "+a = 2" in patch
        assert "+def helper(): return True" in patch
        assert (fixed / "app.py").read_text(encoding="utf-8") == "a = 2\n"
        assert (fixed / "pkg/submodule/new.py").read_text(encoding="utf-8") == "def helper(): return True\n"

    def test_stale_fixed_directory_is_wiped_before_applying(self, tmp_path: Path) -> None:
        loop = _make_loop(tmp_path, {"app.py": "v1\n"})
        fixed = tmp_path / "fixed"
        fixed.mkdir(parents=True, exist_ok=True)
        (fixed / "stale_leftover.txt").write_text("leftover", encoding="utf-8")

        loop._apply_fix([{"path": "app.py", "content": "v2\n"}], fixed)

        assert (fixed / "app.py").read_text(encoding="utf-8") == "v2\n"
        assert not (fixed / "stale_leftover.txt").exists()


class TestPipelineRejectionHandling:
    """Verify that the verification loop pipeline properly catches path escapes and emits ledger events."""

    @pytest.mark.parametrize(
        ("bad_path", "setup_symlink"),
        [
            ("../victim.txt", False),
            ("/tmp/evil_test_absolute.txt", False),
            ("link_to_victim", True),
        ],
    )
    def test_pipeline_catches_path_escape_and_emits_unapplied_fix(
        self, tmp_path: Path, bad_path: str, setup_symlink: bool
    ) -> None:
        outside_victim = tmp_path / "victim.txt"
        outside_victim.write_text("safe", encoding="utf-8")

        loop = _make_loop(tmp_path, {"app.py": "def f(): return 1\n"})
        if setup_symlink:
            (loop.clone / "link_to_victim").symlink_to(outside_victim)

        suspicion = Suspicion(
            id="S-ESCAPE-1",
            vuln_class="path_traversal",
            location={"file": "app.py", "line": 1},
            entry_point="app.f",
            hypothesis="unchecked input",
            source="test",
        )
        verdict = Verdict(
            suspicion_id="S-ESCAPE-1",
            verdict=VerdictValue.PROVEN,
            evidence=Evidence(
                test_path="tests/test_exploit.py",
                fails_on="vulnerable",
                passes_on="",
                runs=3,
                oracle={},
                provenance={},
            ),
        )
        outcome = SuspicionResult(
            suspicion=suspicion,
            verdict=verdict,
            reason="oracle-confirmed",
        )

        class MaliciousFixer:
            name = "malicious-fixer"
            pricing = Pricing()

            def complete(self, role, prompt, schema):
                body = {"files": [{"path": bad_path, "content": "hacked"}]}
                return Completion(json.dumps(body), 10, 10, 1, model="scripted")

        loop.roles.fixer = ModelRole(Role.FIXER, MaliciousFixer())
        work = tmp_path / "out" / "work" / "S-ESCAPE-1"
        work.mkdir(parents=True, exist_ok=True)
        exploit = work / "exploit.py"
        exploit.write_text("def test_exploit(): pass\n", encoding="utf-8")

        loop._fix_verify_package(
            outcome=outcome,
            source="app.py",
            exploit_src="def test_exploit(): pass\n",
            exploit=exploit,
            entry_points=["app.f"],
            work=work,
        )

        assert outcome.fix_verified is False
        assert outside_victim.read_text(encoding="utf-8") == "safe"

        # Check that FIX_PROPOSED event was emitted with applied=False
        events = list(loop.ledger.replay(loop.run_id))
        fix_events = [e for e in events if e.type == EventType.FIX_PROPOSED]
        assert len(fix_events) == 1
        assert fix_events[0].payload.get("applied") is False
        assert "escapes" in fix_events[0].payload.get("error", "") or "invalid" in fix_events[0].payload.get("error", "")

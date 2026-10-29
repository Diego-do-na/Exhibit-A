"""Shared helpers for the oracle red-team PoCs.

Each attack builds a throwaway "app" directory and an exploit test, then runs the
*real* oracle exactly as the product does (``run_oracle`` on the host; same call shape
as ``tests/test_oracle_eval.py``). Nothing here touches ``src/``.
"""
from __future__ import annotations

import sys
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from exhibit_a.oracle import Judgement, run_oracle  # noqa: E402


def run(app_src: str, exploit_src: str, entry_points, *, extra_files=None, timeout=60.0) -> Judgement:
    """Write a one-file app and an exploit test to a temp dir and judge with run_oracle."""
    tmp = Path(tempfile.mkdtemp(prefix="redteam_"))
    app_root = tmp / "app_root"
    app_root.mkdir()
    (app_root / "app.py").write_text(textwrap.dedent(app_src), encoding="utf-8")
    for name, body in (extra_files or {}).items():
        (app_root / name).write_text(textwrap.dedent(body), encoding="utf-8")
    # Keep the exploit in its own directory, DISJOINT from app_root, so that test_dir
    # (the test's parent) does not lexically contain the app, matching the product layout
    # (exploits dir vs. a separate app root).
    tests_dir = tmp / "tests"
    tests_dir.mkdir()
    exploit = tests_dir / "test_exploit.py"
    exploit.write_text(textwrap.dedent(exploit_src), encoding="utf-8")
    return run_oracle(app_root, exploit, set(entry_points), timeout=timeout)


def classify(j: Judgement, *, app_is_safe: bool) -> str:
    """FALSE_PROVEN / SUPPRESSED_TRUE / BLOCKED from a judgement."""
    proven_like = j.observed_effect and j.provenance_ok and j.test_outcome == "failed"
    if app_is_safe and proven_like:
        return "FALSE_PROVEN"
    if (not app_is_safe) and not proven_like:
        return "SUPPRESSED_TRUE"
    return "BLOCKED"


def report(name: str, j: Judgement, *, app_is_safe: bool) -> str:
    verdict = classify(j, app_is_safe=app_is_safe)
    print(f"=== {name} ===")
    print(f"  app_is_safe   : {app_is_safe}")
    print(f"  test_outcome  : {j.test_outcome}")
    print(f"  observed_effect: {j.observed_effect}")
    print(f"  provenance_ok : {j.provenance_ok}")
    print(f"  reason        : {j.reason}")
    print(f"  events        : {len(j.events)}")
    for e in j.events:
        chain = " -> ".join(f.function for f in e.stack)
        print(f"    via_symlink={e.via_symlink} stack={chain}")
    print(f"  >>> RESULT    : {verdict}")
    return verdict

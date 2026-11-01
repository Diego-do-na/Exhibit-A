"""Shared helpers for the Node oracle red-team PoCs.

Each attack builds a throwaway app directory and an exploit test, then runs the
*real* oracle exactly as the product does (``run_oracle`` with
``language="javascript"`` on the host path; same call shape as
``tests/test_oracle_js.py``). Nothing here touches ``src/``.

``GUARD`` mirrors ``spikes/redteam/_harness.py``: ``run_all.py`` sets it to
False to switch the static tripwire (``guard_node.py``) off and show what the
layers below it (signed events, frame admission against the staged manifest,
the app-tree tamper check, route checks, provenance) achieve on their own; the
tripwire is bypassable by obfuscation, so the second column is the one that
matters for forgery.
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import exhibit_a.oracle.oracle as _oracle  # noqa: E402
from exhibit_a.oracle import Judgement, run_oracle  # noqa: E402

# run_all.py sets this to False to switch the static tripwire off.
GUARD = True

# Forensic record of every judged run: tests/test_oracle_js_redteam.py asserts on
# these instead of re-running the attacks. Each entry holds the attack name, the
# guard position, the printed verdict, and the judgement fields behind it.
CALLS: list[dict] = []
_node_channel_problem = _oracle.node_channel_problem


def run(
    app_src: str,
    exploit_src: str,
    entry_points,
    *,
    extra_files=None,
    timeout=60.0,
    effect="canary_read",
    exploit_name="test_exploit.js",
) -> Judgement:
    """Write a one-file app and an exploit test to a temp dir and judge with run_oracle."""
    tmp = Path(tempfile.mkdtemp(prefix="redteam_js_"))
    app_root = tmp / "app_root"
    app_root.mkdir()
    (app_root / "app.js").write_text(textwrap.dedent(app_src), encoding="utf-8")
    for name, body in (extra_files or {}).items():
        (app_root / name).write_text(textwrap.dedent(body), encoding="utf-8")
    # Keep the exploit in its own directory, DISJOINT from app_root, so that test_dir
    # (the test's parent) does not lexically contain the app, matching the product layout.
    tests_dir = tmp / "tests"
    tests_dir.mkdir()
    exploit = tests_dir / exploit_name
    exploit.write_text(textwrap.dedent(exploit_src), encoding="utf-8")
    _oracle.node_channel_problem = (
        _node_channel_problem if GUARD else (lambda path: None)
    )
    try:
        return run_oracle(
            app_root,
            exploit,
            set(entry_points),
            timeout=timeout,
            effect=effect,
            language="javascript",
        )
    finally:
        _oracle.node_channel_problem = _node_channel_problem


def classify(j: Judgement, *, app_is_safe: bool) -> str:
    """FALSE_PROVEN / BLOCKED (safe app) or DETECTED / SUPPRESSED_TRUE (vulnerable app)."""
    proven_like = j.observed_effect and j.provenance_ok and j.test_outcome == "failed"
    if app_is_safe:
        return "FALSE_PROVEN" if proven_like else "BLOCKED"
    return "DETECTED" if proven_like else "SUPPRESSED_TRUE"


def report(name: str, j: Judgement, *, app_is_safe: bool) -> str:
    verdict = classify(j, app_is_safe=app_is_safe)
    CALLS.append({
        "attack": name,
        "guard": GUARD,
        "verdict": verdict,
        "test_outcome": j.test_outcome,
        "observed_effect": j.observed_effect,
        "provenance_ok": j.provenance_ok,
        "reason": j.reason,
        "reason_code": j.reason_code,
        "tree_changes": list(j.app_tree_changes),
        "forged_events": j.forged_events,
        "events": len(j.events),
    })
    print(f"=== {name} ===")
    print(f"  app_is_safe   : {app_is_safe}")
    print(f"  test_outcome  : {j.test_outcome}")
    print(f"  observed_effect: {j.observed_effect}")
    print(f"  provenance_ok : {j.provenance_ok}")
    print(f"  reason        : {j.reason}")
    print(f"  reason_code   : {j.reason_code or '-'}  tree_changes={j.app_tree_changes}  forged={j.forged_events}")
    print(f"  events        : {len(j.events)}")
    for e in j.events:
        chain = " -> ".join(f.function for f in e.stack)
        print(f"    via_symlink={e.via_symlink} stack={chain}")
    print(f"  >>> RESULT    : {verdict}")
    return verdict

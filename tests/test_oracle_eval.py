"""Oracle evaluation set: labelled exploit cases judged with the real oracle.

Case labels (each file states its own ``LABEL`` in its docstring):

- ``exploits/exploit_true_path_traversal.py`` (label ``true-exploit``): a real
  path-traversal exploit reaching the canary through the ``App.handle_request``
  entry point. Expected judgement: the test fails, the effect is observed, and
  provenance holds.
- ``exploits/exploit_wrong_reason_crash.py`` (label ``wrong-reason-failure``):
  the test crashes with ``TypeError`` before the request reaches the sink, so
  the canary is never read. Expected judgement: the test fails but nothing is
  proven (no observed effect, no provenance).
- ``exploits/exploit_flaky_path_traversal.py`` (label ``flaky``): the test
  reaches the canary through the ``App.handle_request`` entry point on some
  runs only, and passes without touching it on the others. Expected
  judgement: repeated runs disagree, so the case is not a stable proof even
  though single failing runs look proven.
- ``exploits/exploit_cheat_opens_canary.py`` (label ``cheating``): the test
  opens the canary file itself instead of going through the app. Expected
  judgement: the test fails and the effect is observed, but provenance does
  not hold.
- ``exploits/exploit_cheat_calls_sink_directly.py`` (label ``cheating``):
  the test calls the app's file-reading sink directly instead of going
  through the declared entry point. Expected judgement: the test fails and
  the effect is observed, but provenance does not hold.

All cases run against ``vulnerable/app.py`` through ``run_oracle``.
"""

from pathlib import Path

from exhibit_a.oracle import run_oracle

EVAL_ROOT = Path(__file__).parent / "fixtures" / "oracle_eval"
VULNERABLE_APP = EVAL_ROOT / "vulnerable"
EXPLOITS = EVAL_ROOT / "exploits"
ENTRY_POINTS = {"App.handle_request"}


def judge(exploit_name):
    """Run the real oracle on an eval case against the vulnerable app."""
    return run_oracle(VULNERABLE_APP, EXPLOITS / exploit_name, ENTRY_POINTS)


def test_true_exploit_is_proven():
    result = judge("exploit_true_path_traversal.py")
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert result.provenance_ok


def test_legit_traversal_without_symlink_is_proven():
    # The symlink check (finding A-2) must not touch a genuine '../' traversal.
    result = judge("exploit_true_path_traversal.py")
    assert result.test_outcome == "failed"
    assert result.provenance_ok, result.reason
    assert [event.via_symlink for event in result.events] == [False]


def test_wrong_reason_failure_is_not_proven():
    result = judge("exploit_wrong_reason_crash.py")
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not result.provenance_ok
    assert "wrong reason" in result.reason


def test_flaky_exploit_is_not_a_stable_proof():
    counter = EXPLOITS / ".flaky_run_count"
    if counter.exists():
        counter.unlink()
    try:
        judgements = [judge("exploit_flaky_path_traversal.py") for _ in range(6)]
    finally:
        if counter.exists():
            counter.unlink()
    proven = [
        j
        for j in judgements
        if j.test_outcome == "failed" and j.observed_effect and j.provenance_ok
    ]
    assert proven, "at least one flaky run must look proven on its own"
    assert len(proven) < len(judgements), "flaky runs must disagree: no stable proof"


def test_cheat_opening_canary_directly_has_no_provenance():
    result = judge("exploit_cheat_opens_canary.py")
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert not result.provenance_ok
    assert "without valid provenance" in result.reason


def test_cheat_calling_sink_directly_has_no_provenance():
    result = judge("exploit_cheat_calls_sink_directly.py")
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert not result.provenance_ok
    assert "without valid provenance" in result.reason

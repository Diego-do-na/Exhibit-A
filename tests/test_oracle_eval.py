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

Both cases run against ``vulnerable/app.py`` through ``run_oracle``.
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


def test_wrong_reason_failure_is_not_proven():
    result = judge("exploit_wrong_reason_crash.py")
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not result.provenance_ok
    assert "wrong reason" in result.reason

"""Offline contract for the canary_dos verdict mapping (TASK 1 investigation).

The batch replay failure for ``redos-search-query`` is:

* recording (2026-11-01): ``invalid_test`` / ``no_effect`` -- the recorded
  exploit asserts ``ratio < 10``; the live run measured 40.6x, so the test
  failed, but 40.6x is below the judge threshold (50x), so the judge
  returned ``no_effect`` and ``classify`` mapped the failed, unproven test
  to ``invalid_test``.
* replay on another machine: ``discarded_unproven`` / ``no_effect`` -- the
  same recorded test now measures a ratio below its own 10x assertion
  (CPU timing is machine-dependent), so the test passes and ``classify``
  maps a passed test to ``discarded_unproven``.

These tests pin that mapping offline (no Docker, no model). They do not
regenerate the recording: updating the recorded verdict requires a real
sandbox replay (Docker) and must not be fabricated by hand.
"""

from exhibit_a.loop.pipeline import classify
from exhibit_a.oracle import Judgement
from exhibit_a.schemas.verdict import VerdictValue


def _judgement(outcome: str, *, observed: bool = False, reason_code: str = "") -> Judgement:
    return Judgement(
        observed_effect=observed,
        provenance_ok=observed,
        reason="contract test",
        test_outcome=outcome,  # type: ignore[arg-type]
        events=[],
        reason_code=reason_code,
    )


def test_no_effect_failed_test_is_invalid_test():
    # Exactly the recorded redos-search-query judgement shape.
    judgement = _judgement("failed", reason_code="no_effect")
    assert classify(judgement) == VerdictValue.INVALID_TEST


def test_no_effect_passed_test_is_discarded_unproven():
    # Exactly the replay shape when the timing ratio drops below the
    # recorded test's own assertion. Same reason_code, different verdict:
    # the flip is driven by the test outcome, not by a judge change.
    judgement = _judgement("passed", reason_code="no_effect")
    assert classify(judgement) == VerdictValue.DISCARDED_UNPROVEN


def test_proven_dos_requires_failed_test_with_observed_effect():
    assert classify(_judgement("failed", observed=True)) == VerdictValue.PROVEN
    assert classify(_judgement("passed", observed=True)) == VerdictValue.DISCARDED_UNPROVEN

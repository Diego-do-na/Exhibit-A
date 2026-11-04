"""Offline contract for the canary_dos verdict mapping (TASK 1 investigation).

The batch replay failure for ``redos-search-query`` is a test-outcome flip
on the same ``no_effect`` reason:

* failed test, ratio below 50x → ``invalid_test`` / ``no_effect``
* passed test (the recorded exploit swallows ``dos_probe``'s assertion
  once the ratio clears 50x) → ``discarded_unproven`` / ``no_effect``

Compact metadata now stores the CI sandbox shape
(``discarded_unproven`` / ``no_effect``), taken from the shard 4 log, not
invented offline.

These tests pin the mapping itself (no Docker, no model).
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
    judgement = _judgement("failed", reason_code="no_effect")
    assert classify(judgement) == VerdictValue.INVALID_TEST


def test_no_effect_passed_test_is_discarded_unproven():
    # Compact redos-search-query metadata after the CI sandbox replay.
    judgement = _judgement("passed", reason_code="no_effect")
    assert classify(judgement) == VerdictValue.DISCARDED_UNPROVEN


def test_proven_dos_requires_failed_test_with_observed_effect():
    assert classify(_judgement("failed", observed=True)) == VerdictValue.PROVEN
    assert classify(_judgement("passed", observed=True)) == VerdictValue.DISCARDED_UNPROVEN

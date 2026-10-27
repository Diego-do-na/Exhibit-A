"""Oracle tests: true exploit, wrong-reason failure, cheating tests, fixed app."""

from pathlib import Path

import pytest

from exhibit_a.oracle import run_oracle

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
EXPLOITS = FIXTURES / "exploits"
ENTRY_POINTS = {"App.handle_request"}


def judge(app, exploit, **kwargs):
    return run_oracle(FIXTURES / app, EXPLOITS / exploit, ENTRY_POINTS, **kwargs)


def test_true_exploit_is_proven():
    result = judge("vulnerable", "exploit_traversal.py")
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert result.provenance_ok
    assert len(result.events) == 1
    functions = [f.qualname for f in result.events[0].stack]
    assert "App.handle_request" in functions and "read_file" in functions


def test_exploit_passes_on_fixed_app_without_effect():
    result = judge("fixed", "exploit_traversal.py")
    assert result.test_outcome == "passed"
    assert not result.observed_effect
    assert not result.provenance_ok
    assert result.events == []


def test_wrong_reason_failure_has_no_effect():
    result = judge("vulnerable", "exploit_crashes_early.py")
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not result.provenance_ok
    assert "wrong reason" in result.reason


def test_cheating_test_calling_sink_directly_fails_provenance():
    result = judge("vulnerable", "exploit_cheating.py")
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert not result.provenance_ok
    assert "entry point" in result.reason


def test_cheating_test_reading_canary_itself_fails_provenance():
    result = judge("vulnerable", "exploit_reads_itself.py")
    assert result.observed_effect
    assert not result.provenance_ok
    assert "itself" in result.reason


def test_undeclared_entry_point_fails_provenance():
    result = run_oracle(FIXTURES / "vulnerable", EXPLOITS / "exploit_traversal.py", {"other"})
    assert result.observed_effect
    assert not result.provenance_ok


def test_timeout_is_reported():
    result = judge("vulnerable", "exploit_hangs.py", timeout=2)
    assert result.test_outcome == "timeout"
    assert not result.observed_effect


@pytest.mark.parametrize("exploit", ["exploit_traversal.py", "exploit_cheating.py"])
def test_canary_token_differs_per_run(exploit):
    # Each run plants a fresh canary, so a test cannot hardcode its content.
    a = judge("vulnerable", exploit)
    b = judge("vulnerable", exploit)
    assert a.events[0].path != b.events[0].path

import json

import pytest
from pydantic import ValidationError

from exhibit_a.schemas import (
    Event,
    EventType,
    RepoProfile,
    Suspicion,
    Verdict,
    VerdictValue,
)

PROFILE = {
    "commit": "abc123",
    "language": "python",
    "interpreter": "python3.11",
    "dependency_manager": "pip",
    "install_cmd": "pip install -e .",
    "test_cmd": "pytest",
    "framework": "flask",
    "dependencies": [{"name": "flask", "version": "3.0.0"}],
    "baseline": {"passed": 10, "failed": 0, "seconds": 1.5},
}

SUSPICION = {
    "id": "s1",
    "class": "path_traversal",
    "location": {"file": "app.py", "line": 42},
    "entry_point": "GET /download",
    "hypothesis": "filename is joined without normalization",
    "source": "adversary",
}

VERDICT = {
    "suspicion_id": "s1",
    "verdict": "proven",
    "evidence": {
        "test_path": "tests/test_exploit.py",
        "fails_on": "abc123",
        "passes_on": "def456",
        "runs": 3,
        "oracle": {"canary_read": True},
        "provenance": {"entry_point": "GET /download"},
    },
    "fix": {"patch_path": "fix.patch"},
    "bypass_attempts": {"tried": 2, "succeeded": 0},
}

EVENT = {
    "ts": "2026-10-27T12:00:00Z",
    "run_id": "r1",
    "type": "verdict",
    "role": "adversary",
    "model": "replay",
    "tokens_in": 10,
    "tokens_out": 5,
    "cost_usd": 0.001,
    "latency_ms": 120,
    "payload": {"k": "v"},
}


@pytest.mark.parametrize(
    "model,data",
    [(RepoProfile, PROFILE), (Suspicion, SUSPICION), (Verdict, VERDICT), (Event, EVENT)],
)
def test_valid_and_unknown_field_rejected(model, data):
    model.model_validate(data)
    with pytest.raises(ValidationError):
        model.model_validate({**data, "extra": 1})


def test_nested_unknown_field_rejected():
    bad = {**PROFILE, "baseline": {**PROFILE["baseline"], "oops": 1}}
    with pytest.raises(ValidationError):
        RepoProfile.model_validate(bad)


def test_missing_required_field():
    bad = {k: v for k, v in PROFILE.items() if k != "commit"}
    with pytest.raises(ValidationError):
        RepoProfile.model_validate(bad)


def test_verdict_values():
    assert {v.value for v in VerdictValue} == {
        "proven", "discarded_unproven", "invalid_test", "flaky", "env_failure",
    }
    with pytest.raises(ValidationError):
        Verdict.model_validate({**VERDICT, "verdict": "safe"})


def test_event_types():
    assert len(EventType) == 12
    with pytest.raises(ValidationError):
        Event.model_validate({**EVENT, "type": "nope"})


def test_negative_numbers_rejected():
    with pytest.raises(ValidationError):
        Event.model_validate({**EVENT, "tokens_in": -1})
    with pytest.raises(ValidationError):
        RepoProfile.model_validate({**PROFILE, "baseline": {"passed": -1, "failed": 0, "seconds": 0}})


def test_suspicion_class_alias():
    s = Suspicion.model_validate(SUSPICION)
    assert s.vuln_class == "path_traversal"
    assert json.loads(s.to_json())["class"] == "path_traversal"
    with pytest.raises(ValidationError):
        Suspicion.model_validate({**SUSPICION, "vuln_class": "x", "class": "y"} | {"bogus": 1})


@pytest.mark.parametrize(
    "model,data",
    [(RepoProfile, PROFILE), (Verdict, VERDICT), (Event, EVENT)],
)
def test_json_round_trip(model, data):
    obj = model.model_validate(data)
    again = model.model_validate_json(obj.model_dump_json())
    assert again == obj
    assert json.loads(obj.model_dump_json()) == data


def test_suspicion_round_trip():
    s = Suspicion.model_validate(SUSPICION)
    assert Suspicion.model_validate_json(s.to_json()) == s
    assert json.loads(s.to_json()) == SUSPICION

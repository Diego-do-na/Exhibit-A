from __future__ import annotations

from exhibit_a.dashboard.model import run_detail
from exhibit_a.dashboard.sources import RunData, RunRef
from exhibit_a.live.summary import build_summary
from exhibit_a.schemas import Event


def _event(seq: int, kind: str, payload: dict) -> Event:
    return Event.model_validate(
        {
            "ts": f"2026-10-31T12:00:0{seq}Z",
            "run_id": "run-v3",
            "type": kind,
            "payload": payload,
        }
    )


def _events() -> list[Event]:
    hostile = '<script>alert("duplicate")</script>'
    return [
        _event(
            1,
            "suspicion_raised",
            {
                "suspicion": {
                    "id": "primary",
                    "class": "sql_injection",
                    "location": {"file": "app.py", "line": 8},
                    "entry_point": "main",
                }
            },
        ),
        _event(
            2,
            "suspicion_raised",
            {
                "suspicion": {
                    "id": hostile,
                    "class": "sql_injection",
                    "location": {"file": "app.py", "line": 12},
                    "entry_point": "main",
                }
            },
        ),
        _event(
            3,
            "verdict",
            {
                "suspicion_id": "primary",
                "verdict": "proven",
                "facts": {
                    "effect": "canary_sql",
                    "observed_location": {
                        "file": "db.py",
                        "line": 44,
                        "line_source": "graph_sink_call",
                    },
                },
                "duplicates": [hostile],
            },
        ),
        _event(
            4,
            "verdict",
            {
                "suspicion_id": hostile,
                "verdict": "proven",
                "duplicate_of": "primary",
                "facts": {
                    "effect": "canary_sql",
                    "observed_location": {"file": "db.py", "line": 44},
                },
            },
        ),
    ]


def test_dashboard_groups_duplicate_proofs_and_keeps_locations_as_data():
    detail = run_detail(RunData(ref=RunRef("run-v3"), events=_events()))

    assert detail["proven_raw"] == 2
    assert detail["duplicates"] == 1
    assert len(detail["proven"]) == 1
    finding = detail["proven"][0]
    assert finding["evidence"]["model_location"] == {"file": "app.py", "line": 8}
    assert finding["evidence"]["observed_location"]["file"] == "db.py"
    assert finding["evidence"]["cwe"] == "CWE-89"
    assert finding["evidence"]["severity"] == "critical"
    assert finding["evidence"]["duplicates"][0]["suspicion_id"] == '<script>alert("duplicate")</script>'
    assert {entry["value"] for entry in detail["effect_schema"]} == {
        "canary_read",
        "canary_write",
        "canary_exec",
        "canary_sql",
        "canary_connect",
        "canary_dos",
    }


def test_live_summary_uses_unique_findings_and_preserves_hostile_duplicate_text():
    summary = build_summary(_events())

    assert summary["proven"] == 1
    assert summary["proven_raw"] == 2
    assert summary["duplicates"] == 1
    assert summary["findings"][0]["observed_location"]["file"] == "db.py"
    assert summary["findings"][0]["duplicates"][0]["suspicion_id"].startswith("<script>")

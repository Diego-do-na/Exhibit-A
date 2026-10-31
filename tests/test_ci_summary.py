"""Tests for the CI summary helpers (exhibit_a.ci.summary)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from exhibit_a.ci import summary
from exhibit_a.ci.summary import (
    COMMENT_MARKER,
    SCHEMA_VERSION,
    build_result,
    exit_code,
    find_marker_comment,
    render_comment,
    render_markdown,
    step_outputs,
)
from exhibit_a.ledger import Ledger
from exhibit_a.schemas import Event

FULL = {"naive": False, "oracle": True, "differential": True, "defender": True}


def ev(type_: str, run_id: str = "r1", **payload: Any) -> Event:
    return Event(ts="2026-10-29T00:00:00Z", run_id=run_id, type=type_, payload=payload)


def suspicion(sid: str, run_id: str = "r1") -> Event:
    return ev("suspicion_raised", run_id, suspicion={"id": sid})


def completed_run(*verdicts: tuple[str, str], run_id: str = "r1") -> list[Event]:
    events = [ev("baseline_done", run_id, ok=True, outcome="passed", flags=FULL)]
    for sid, value in verdicts:
        events.append(suspicion(sid, run_id))
        events.append(ev("verdict", run_id, suspicion_id=sid, verdict=value, reason=f"why {sid}"))
    return events


def _no_safe_claim(text: str) -> None:
    assert not re.search(r"\bsafe\b", text, re.IGNORECASE), text


# -- build_result -------------------------------------------------------------------


def test_no_events_is_not_run_and_green() -> None:
    result = build_result([])
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["status"] == "not_run"
    assert result["proven"] == 0
    assert exit_code(result, "proven") == 0
    assert "nothing could be proven" in render_markdown(result).lower()


def test_completed_without_proof() -> None:
    result = build_result(completed_run(("s1", "discarded_unproven"), ("s2", "flaky")))
    assert result["status"] == "completed"
    assert result["proven"] == 0
    assert result["dropped"] == 2
    assert result["suspicions_raised"] == 2
    assert result["verdicts"]["flaky"] == 1
    assert exit_code(result, "proven") == 0
    md = render_markdown(result)
    assert "Nothing could be proven" in md
    _no_safe_claim(md)


def test_proven_finding_turns_the_gate_red() -> None:
    events = completed_run(("s1", "proven"), ("s2", "invalid_test"))
    events.append(ev("packaged", suspicion_id="s1", path="packages/s1", fix_verified=True))
    result = build_result(events)
    assert result["proven"] == 1
    assert result["dropped"] == 1
    assert result["findings"] == [
        {"suspicion_id": "s1", "reason": "why s1", "fix_verified": True, "package": "packages/s1"}
    ]
    assert exit_code(result, "proven") == 1
    assert exit_code(result, "never") == 0
    md = render_markdown(result)
    assert "1 proven finding" in md
    assert "Proven findings" in md


def test_proven_without_package_is_still_proven_but_fix_unverified() -> None:
    result = build_result(completed_run(("s1", "proven")))
    assert result["findings"][0]["fix_verified"] is False
    assert exit_code(result, "proven") == 1


def test_latest_verdict_per_suspicion_wins() -> None:
    events = completed_run(("s1", "proven"))
    events.append(ev("verdict", suspicion_id="s1", verdict="flaky", reason="rerun"))
    result = build_result(events)
    assert result["proven"] == 0
    assert result["verdicts"]["flaky"] == 1


def test_only_verdict_events_count() -> None:
    # A model output that merely mentions "proven" never makes a finding.
    events = completed_run(("s1", "discarded_unproven"))
    events.append(ev("oracle_event", suspicion_id="s1", verdict="proven"))
    events.append(ev("packaged", suspicion_id="s1", path="x", fix_verified=True))
    assert build_result(events)["proven"] == 0


def test_baseline_failure_is_aborted() -> None:
    result = build_result([ev("baseline_done", ok=False, outcome="failed", flags=FULL)])
    assert result["status"] == "aborted"
    assert exit_code(result, "proven") == 0
    md = render_markdown(result)
    assert "aborted" in md.lower()
    assert "nothing could be proven" in md.lower()


def test_fixed_code_baseline_does_not_mark_abort() -> None:
    events = completed_run(("s1", "proven"))
    events.append(ev("baseline_done", suspicion_id="s1", on="fixed", ok=False))
    assert build_result(events)["status"] == "completed"


def test_unjudged_suspicions_mean_aborted() -> None:
    events = completed_run(("s1", "discarded_unproven"))
    events.append(suspicion("s2"))
    assert build_result(events)["status"] == "aborted"


def test_naive_ablation_is_flagged() -> None:
    naive = dict(FULL, naive=True)
    events = [ev("baseline_done", ok=True, flags=naive), suspicion("s1")]
    result = build_result(events)
    assert result["status"] == "completed"
    assert result["ablated"] is True
    assert "ablation" in render_markdown(result)


def test_timeout_and_skip_statuses() -> None:
    assert build_result([], engine_exit=124)["status"] == "timed_out"
    assert build_result(completed_run(), engine_exit=1)["status"] == "completed"
    skipped = build_result([], skipped_reason="docs/tests only", risk={"risk": "low"})
    assert skipped["status"] == "skipped"
    md = render_markdown(skipped)
    assert "nothing could be proven" in md.lower()
    assert "docs/tests only" in md
    assert "`low`" in md


def test_selects_one_run() -> None:
    events = completed_run(("a", "proven"), run_id="old") + completed_run(
        ("b", "flaky"), run_id="new"
    )
    assert build_result(events)["run_id"] == "new"
    assert build_result(events)["proven"] == 0
    assert build_result(events, run_id="old")["proven"] == 1


def test_unknown_verdict_label_is_counted() -> None:
    events = completed_run(("s1", "weird"))
    result = build_result(events)
    assert result["verdicts"]["weird"] == 1
    assert result["proven"] == 0


def test_usage_totals() -> None:
    events = completed_run()
    events.append(Event(ts="t", run_id="r1", type="suspicion_raised", tokens_in=5,
                        tokens_out=7, cost_usd=0.25, payload={}))
    events.append(ev("verdict", suspicion_id="x", verdict="flaky"))
    result = build_result(events)
    assert (result["tokens_in"], result["tokens_out"], result["cost_usd"]) == (5, 7, 0.25)


def test_result_is_json_serialisable() -> None:
    result = build_result(completed_run(("s1", "proven")), risk={"risk": "high"})
    assert json.loads(json.dumps(result)) == result


def test_exit_code_rejects_unknown_policy() -> None:
    with pytest.raises(ValueError):
        exit_code(build_result([]), "always")


def test_step_outputs() -> None:
    out = step_outputs(build_result(completed_run(("s1", "proven"), ("s2", "env_failure"))))
    assert out["proven"] == "1"
    assert out["env-failure"] == "1"
    assert out["discarded-unproven"] == "0"
    assert out["status"] == "completed"
    assert all(isinstance(v, str) and "\n" not in v for v in out.values())


# -- rendering and untrusted text ---------------------------------------------------


def test_untrusted_text_is_escaped() -> None:
    hostile = (
        "<img src=x onerror=alert(1)> | @maintainer [click](https://evil) "
        f"{COMMENT_MARKER}\n## heading"
    )
    events = completed_run()
    events.append(suspicion(hostile))
    events.append(ev("verdict", suspicion_id=hostile, verdict="proven", reason=hostile))
    md = render_markdown(build_result(events))
    assert "<img" not in md
    assert "@maintainer" not in md
    assert COMMENT_MARKER not in md
    assert "\n## heading" not in md
    assert "[click](" not in md
    # Table rows stay one line each with exactly four cell separators.
    row = next(line for line in md.splitlines() if "img" in line)
    assert row.count("|") - row.count("\\|") == 4


def test_long_text_is_truncated() -> None:
    events = completed_run(("s1", "proven"))
    events[-1] = ev("verdict", suspicion_id="s1", verdict="proven", reason="x" * 5000)
    md = render_markdown(build_result(events))
    assert "x" * 400 not in md


@pytest.mark.parametrize(
    "events",
    [[], completed_run(("s1", "proven")), completed_run(("s1", "flaky"))],
)
def test_no_render_claims_safety(events: list[Event]) -> None:
    for kwargs in ({}, {"engine_exit": 124}, {"skipped_reason": "low risk"}):
        result = build_result(events, **kwargs)
        _no_safe_claim(render_markdown(result))
        _no_safe_claim(render_comment(result))


def test_comment_has_marker_first() -> None:
    body = render_comment(build_result([]))
    assert body.startswith(COMMENT_MARKER + "\n")
    assert body.count(COMMENT_MARKER) == 1


def test_find_marker_comment_is_idempotent_and_author_bound() -> None:
    bot = {"login": "github-actions[bot]"}
    comments = [
        {"id": 5, "body": "hello", "user": bot},
        {"id": 9, "body": f"> quoting\n{COMMENT_MARKER}", "user": bot},
        {"id": 7, "body": f"{COMMENT_MARKER}\nfrom a human", "user": {"login": "alice"}},
        {"id": 12, "body": f"{COMMENT_MARKER}\nold", "user": bot},
        {"id": 11, "body": f"{COMMENT_MARKER}\nolder", "user": bot},
    ]
    assert find_marker_comment(comments) == 11
    assert find_marker_comment(comments[:3]) is None
    assert find_marker_comment([], "x") is None
    assert find_marker_comment(comments, author="alice") == 7
    assert find_marker_comment([{"id": "13", "body": COMMENT_MARKER, "user": bot}]) is None


# -- CLI ----------------------------------------------------------------------------


def _write_ledger(path: Path, events: list[Event]) -> None:
    ledger = Ledger(path)
    for event in events:
        ledger.append(event)


def test_cli_build_writes_files_and_outputs(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _write_ledger(ledger, completed_run(("s1", "proven")))
    risk = tmp_path / "risk.json"
    risk.write_text(json.dumps({"risk": "high", "should_run_exploits": True}), encoding="utf-8")
    step = tmp_path / "step.md"
    gh_out = tmp_path / "out.txt"
    out = tmp_path / "result"
    code = summary.main([
        "build", "--ledger", str(ledger), "--out-dir", str(out), "--risk", str(risk),
        "--engine-exit", "1", "--step-summary", str(step), "--github-output", str(gh_out),
    ])
    assert code == 0  # not gating unless --gate
    data = json.loads((out / "result.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["proven"] == 1
    assert data["risk"]["risk"] == "high"
    assert (out / "comment.md").read_text(encoding="utf-8").startswith(COMMENT_MARKER)
    assert "1 proven finding" in step.read_text(encoding="utf-8")
    pairs = dict(line.split("=", 1) for line in gh_out.read_text(encoding="utf-8").splitlines())
    assert pairs["proven"] == "1"
    assert pairs["exit-code"] == "1"


def test_cli_build_gate_and_missing_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    _write_ledger(ledger, completed_run(("s1", "proven")))
    args = ["build", "--ledger", str(ledger), "--out-dir", str(tmp_path / "o"), "--gate"]
    assert summary.main(args) == 1
    assert summary.main(args + ["--fail-on", "never"]) == 0
    missing = ["build", "--ledger", str(tmp_path / "nope.jsonl"), "--out-dir", str(tmp_path / "m"), "--gate"]
    assert summary.main(missing) == 0
    data = json.loads((tmp_path / "m" / "result.json").read_text(encoding="utf-8"))
    assert data["status"] == "not_run"


def test_cli_build_corrupt_ledger_fails_loudly(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("{not json\n", encoding="utf-8")
    assert summary.main(["build", "--ledger", str(ledger), "--out-dir", str(tmp_path / "o")]) == 2


def test_cli_find_comment(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bot = {"login": "github-actions[bot]"}
    pages = [[{"id": 1, "body": "x", "user": bot}], [{"id": 4, "body": COMMENT_MARKER, "user": bot}]]
    path = tmp_path / "comments.json"
    path.write_text(json.dumps(pages), encoding="utf-8")
    assert summary.main(["find-comment", str(path)]) == 0
    assert capsys.readouterr().out.strip() == "4"
    path.write_text("[]", encoding="utf-8")
    assert summary.main(["find-comment", str(path)]) == 0
    assert capsys.readouterr().out.strip() == ""


# -- findings: unique counts, the opening explanation, hostile facts -----------------------


def _facts(*frames: str, effect: str = "canary_read") -> dict[str, Any]:
    chain = [{"file": "app.py", "qualname": name, "line": 10 + n} for n, name in enumerate(frames)]
    return {"effect": effect, "entry_point": frames[0], "sink_function": frames[-1], "chain": chain,
            "observed_location": {"file": "app.py", "line": 63, "function": frames[-1],
                                  "line_source": "graph_sink_call"},
            "runs": 3, "test": "test_exploit.py", "fix_verified": True}


def _proven(sid: str, facts: Any, hypothesis: str = "a guess") -> list[Event]:
    return [
        ev("suspicion_raised", suspicion={"id": sid, "hypothesis": hypothesis}),
        ev("verdict", suspicion_id=sid, verdict="proven", reason=f"why {sid}", **({"facts": facts} if facts is not None else {})),
        ev("packaged", suspicion_id=sid, path=f"packages/{sid}", fix_verified=True),
    ]


def _run(*groups: list[Event]) -> list[Event]:
    return [ev("baseline_done", ok=True, outcome="passed", flags=FULL), *[e for g in groups for e in g]]


def test_two_proofs_of_one_effect_count_as_one_finding_and_keep_the_raw_count() -> None:
    events = _run(_proven("S1", _facts("Entry.go", "sink")), _proven("S3", _facts("Entry.go", "sink")))
    result = build_result(events)
    assert (result["proven"], result["proven_raw"], result["duplicates"]) == (1, 2, 1)
    assert result["verdicts"]["proven"] == 2 and result["dropped"] == 0
    [finding] = result["findings"]
    assert finding["suspicion_id"] == "S1"
    assert finding["duplicates"] == [{"suspicion_id": "S3", "package": "packages/S3"}]
    assert exit_code(result, "proven") == 1
    assert "1 proven finding" in render_markdown(result)


def test_different_effects_entry_points_or_sinks_stay_separate_findings() -> None:
    events = _run(
        _proven("S1", _facts("Entry.go", "sink")),
        _proven("S2", _facts("Entry.go", "sink", effect="canary_write")),
        _proven("S3", _facts("Other.go", "sink")),
        _proven("S4", _facts("Entry.go", "other_sink")),
        _proven("S5", None),
    )
    result = build_result(events)
    assert (result["proven"], result["proven_raw"], result["duplicates"]) == (5, 5, 0)
    assert all("duplicates" not in f for f in result["findings"])


def test_each_finding_opens_with_oracle_facts_then_the_models_guess() -> None:
    result = build_result(_run(_proven("S1", _facts("Entry.go", "sink"), hypothesis="Windows backslashes")))
    [finding] = result["findings"]
    assert finding["observed_location"]["line"] == 63 and finding["hypothesis"] == "Windows backslashes"
    section = render_markdown(result).split("### Proven findings", 1)[1]
    assert section.index("The oracle observed that") < section.index("Model's hypothesis")
    assert "at app.py:63" in section and "The fix was verified" in section
    assert "the model's guess; the oracle did not observe it" in section
    assert section.index("Model's hypothesis") < section.index("| Suspicion |")


def test_a_finding_without_facts_is_not_given_an_explanation() -> None:
    result = build_result(completed_run(("s1", "proven")))
    assert "The oracle observed" not in render_markdown(result)


def test_hostile_ledger_facts_are_bounded_and_escaped() -> None:
    facts = _facts("Entry.go", "sink")
    facts["entry_point"] = "<img src=x onerror=alert(1)> @team " + "A" * 5000
    facts["observed_location"]["file"] = "[x](javascript:y)"
    facts["injected"] = "SAFE: nothing to see"
    result = build_result(_run(_proven("S1", facts, hypothesis="<script>alert(1)</script> @everyone")))
    assert "injected" not in result["findings"][0]["facts"]
    assert len(result["findings"][0]["facts"]["entry_point"]) <= 300
    text = render_markdown(result)
    assert "<img" not in text and "<script>" not in text and "](javascript" not in text
    assert "@team" not in text.replace("@\u200bteam", "") and "@everyone" not in text.replace("@\u200beveryone", "")
    assert build_result(_run(_proven("S1", "not a mapping")))["proven"] == 1

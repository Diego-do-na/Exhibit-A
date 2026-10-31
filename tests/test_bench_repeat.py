from pathlib import Path

from bench.corpus import Case
from bench.repeat import aggregate, execute, regenerate_document, render_table


def _case(case_id: str, vulnerable: bool) -> Case:
    return Case(
        id=case_id,
        kind="vulnerable" if vulnerable else "fixed",
        repo="",
        commit="",
        ground_truth=({"class": "x", "file": "app.py"},) if vulnerable else (),
        case_dir="/tmp/case",
    )


def test_table_math_and_negative_control_detection():
    rows = [
        {"case": "v", "mode": "compact", "proven": 1, "fix_verified": 1,
         "input_tokens": 10, "tokens": 20, "cost": 0.2,
         "verdict_counts": {"invalid_test": 2}},
        {"case": "v", "mode": "compact", "proven": 0, "fix_verified": 0,
         "input_tokens": 30, "tokens": 40, "cost": 0.4,
         "verdict_counts": {"invalid_test": 0}},
        {"case": "n", "mode": "compact", "proven": 1, "fix_verified": 0,
         "input_tokens": 5, "tokens": 5, "cost": 0.1,
         "negative_control": True, "verdict_counts": {"invalid_test": 1}},
    ]
    result = {row["case"]: row for row in aggregate(rows)}
    assert result["v"]["runs_proven"] == 1
    assert result["v"]["mean_input_tokens"] == 20
    assert result["v"]["cost_range"] == [0.2, 0.4]
    assert result["n"]["false_proofs"] == 1
    assert "0.3000" in render_table(rows)


def test_execute_stops_at_budget_and_writes_json(tmp_path: Path):
    case = _case("v", True)
    calls = []

    def fake_runner(case, mode, out, budget):
        calls.append((mode, budget))
        return {
            "case": case.id, "mode": mode, "proven": 0, "fix_verified": 0,
            "input_tokens": 1, "tokens": 2, "cost": 0.6,
            "verdict_counts": {}, "unique_findings": [],
        }

    payload = execute([case], ["compact"], 3, 1.0, tmp_path, fake_runner)
    assert len(calls) == 2
    assert payload["total_usd"] == 1.2
    assert len(payload["runs"]) == 2
    assert (tmp_path / "repeat.json").is_file()


def test_regeneration_replaces_only_marked_section(tmp_path: Path):
    doc = tmp_path / "repeatability.md"
    doc.write_text("before\n\n<!-- BEGIN REPEATABILITY -->\nold\n<!-- END REPEATABILITY -->\n\nafter\n")
    regenerate_document(doc, {"runs": [{
        "case": "v", "mode": "compact", "proven": 1, "fix_verified": 1,
        "input_tokens": 1, "tokens": 1, "cost": 0.1,
        "verdict_counts": {},
    }]})
    text = doc.read_text()
    assert "before" in text and "after" in text
    assert "| v | compact | 1 / 1" in text
    assert "old" not in text

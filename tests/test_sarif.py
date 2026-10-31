"""Tests for SARIF 2.1.0 export, CWE mapping, and deterministic severity rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.record_meta import DEFAULT_MODEL, replay_case
from exhibit_a.cli.ext.sarif import cmd_sarif
from exhibit_a.report.cwe import (
    CWE_22,
    CWE_73,
    CWE_78,
    CWE_89,
    CWE_95,
    CWE_502,
    CWE_TABLE,
    get_cwe,
    sarif_level_from_severity,
    security_severity_score,
    severity_from_effect,
)
from exhibit_a.report.sarif import generate_sarif, validate_sarif


# -- CWE Mappings and Severity --------------------------------------------------


def test_cwe_table_mappings() -> None:
    # Path traversal CWE-22
    assert get_cwe("canary_read", "path_traversal") == CWE_22
    assert get_cwe("read", "path_traversal") == CWE_22
    assert get_cwe("canary_write", "path_traversal") == CWE_22

    # Arbitrary file write / zip slip: CWE-73 / CWE-22
    assert get_cwe("canary_write", "archive_extraction_path_traversal") == CWE_22
    assert get_cwe("canary_write", "arbitrary_file_write") == CWE_73
    assert get_cwe("write", "arbitrary_file_write") == CWE_73

    # OS command injection CWE-78
    assert get_cwe("canary_exec", "command_injection") == CWE_78
    assert get_cwe("exec", "os_command_injection") == CWE_78

    # Unsafe deserialization CWE-502
    assert get_cwe("canary_exec", "insecure_deserialization") == CWE_502
    assert get_cwe("exec", "unsafe_deserialization") == CWE_502

    # Dynamic eval injection CWE-95
    assert get_cwe("canary_exec", "code_injection") == CWE_95
    assert get_cwe("exec", "eval_injection") == CWE_95

    # SQL injection CWE-89
    assert get_cwe("sql", "sql_injection") == CWE_89
    assert get_cwe("canary_sql", "sql_injection") == CWE_89


def test_severity_derived_from_proven_effect_never_model_text() -> None:
    # 1. Exec & SQL: critical when proven through entry point with provenance, high otherwise
    assert severity_from_effect("canary_exec", provenance_ok=True, has_entry_point=True) == "critical"
    assert severity_from_effect("exec", provenance_ok=False, has_entry_point=True) == "high"
    assert severity_from_effect("exec", provenance_ok=True, has_entry_point=False) == "high"
    assert severity_from_effect("sql", provenance_ok=True, has_entry_point=True) == "critical"
    assert severity_from_effect("sql", provenance_ok=False, has_entry_point=True) == "high"

    # 2. Write: high
    assert severity_from_effect("canary_write", provenance_ok=True, has_entry_point=True) == "high"
    assert severity_from_effect("write", provenance_ok=False, has_entry_point=False) == "high"

    # 3. Read: high with authenticated entry point, medium otherwise
    assert severity_from_effect("canary_read", provenance_ok=True, has_entry_point=True) == "high"
    assert severity_from_effect("read", provenance_ok=False, has_entry_point=True) == "medium"
    assert severity_from_effect("canary_read", provenance_ok=True, has_entry_point=False) == "medium"

    # SARIF level mapping
    assert sarif_level_from_severity("critical") == "error"
    assert sarif_level_from_severity("high") == "error"
    assert sarif_level_from_severity("medium") == "warning"
    assert sarif_level_from_severity("low") == "note"

    # Security severity scores
    assert security_severity_score("critical") == "9.0"
    assert security_severity_score("high") == "7.5"
    assert security_severity_score("medium") == "5.0"


# -- SARIF Generation -----------------------------------------------------------


def test_sarif_empty_run_produces_valid_sarif_with_zero_results(tmp_path: Path) -> None:
    sarif = generate_sarif(tmp_path)
    validate_sarif(sarif)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Exhibit A"
    assert run["results"] == []


def test_sarif_discarded_suspicions_are_not_results(tmp_path: Path) -> None:
    pkg = tmp_path / "packages" / "unproven-suspicion"
    pkg.mkdir(parents=True)
    verdict = {
        "suspicion_id": "S-UNPROVEN",
        "verdict": "discarded_unproven",
        "reason": "exploit did not trigger canary",
    }
    (pkg / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    sarif = generate_sarif(tmp_path)
    validate_sarif(sarif)
    assert sarif["runs"][0]["results"] == []


def test_sarif_proven_package_structure(tmp_path: Path) -> None:
    pkg = tmp_path / "packages" / "proven-finding"
    pkg.mkdir(parents=True)

    suspicion = {
        "id": "S1",
        "class": "path_traversal",
        "location": {"file": "app/views.py", "line": 42},
        "entry_point": "App.route",
        "hypothesis": "Untrusted filename parameter leads to path escape",
    }
    evidence = {
        "suspicion": suspicion,
        "suspicious_code": {"file": "app/views.py", "line": 42, "content": "open(path)"},
        "fix_verified": True,
        "evidence": {
            "test_path": "test_exploit.py",
            "passes_on": "fixed",
            "oracle": {
                "effect": "canary_read",
                "events": [
                    {
                        "type": "canary_read",
                        "path": "/oracle/canary",
                        "stack": [
                            {"file": "/clone/app/views.py", "function": "route", "qualname": "App.route", "line": 20, "admitted": True},
                            {"file": "/clone/app/views.py", "function": "read_doc", "qualname": "App.read_doc", "line": 45, "admitted": True},
                        ],
                    }
                ],
            },
            "provenance": {"ok": True, "entry_point": "App.route"},
        },
        "usage": {"cost_usd": 0.042},
    }
    verdict = {
        "suspicion_id": "S1",
        "verdict": "proven",
        "evidence": evidence["evidence"],
    }
    (pkg / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    (pkg / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    sarif = generate_sarif(tmp_path)
    validate_sarif(sarif)

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    res = results[0]

    assert res["ruleId"] == "CWE-22"
    assert res["level"] == "error"
    # Observed location: line 45 (sink frame) rather than model line 42
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 45
    assert "views.py" in res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    # Properties
    props = res["properties"]
    assert props["effect"] == "canary_read"
    assert props["verdict"] == "proven"
    assert props["fix_verified"] is True
    assert props["cost"] == 0.042
    assert props["package_path"] == "packages/proven-finding"

    # Code flow: entry point to sink
    assert "codeFlows" in res
    flows = res["codeFlows"]
    assert len(flows) == 1
    steps = flows[0]["threadFlows"][0]["locations"]
    assert len(steps) == 2
    assert "App.route" in steps[0]["location"]["message"]["text"]
    assert "App.read_doc" in steps[1]["location"]["message"]["text"]


@pytest.mark.docker
def test_sarif_replayed_archive_run_acceptance_criterion(tmp_path: Path, monkeypatch) -> None:
    """Acceptance criteria: results.sarif for a replayed archive run has one result with CWE-22 and a code flow."""
    monkeypatch.delenv("META_API_KEY", raising=False)
    out_dir = tmp_path / "replay_archive"
    outcome = replay_case("archive-extraction-pathtraversal", DEFAULT_MODEL, out_dir, "compact")
    assert outcome.baseline_ok

    sarif = generate_sarif(out_dir)
    validate_sarif(sarif)

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    finding = results[0]

    # Acceptance criteria verification
    assert finding["ruleId"] == "CWE-22"
    assert finding["level"] == "error"
    assert finding["properties"]["effect"] == "canary_write"
    assert finding["properties"]["verdict"] == "proven"
    assert finding["properties"]["fix_verified"] is True

    # Code flow from admitted stack entry point to sink
    assert "codeFlows" in finding
    flows = finding["codeFlows"]
    assert len(flows) == 1
    steps = flows[0]["threadFlows"][0]["locations"]
    assert len(steps) >= 2

    # Step 1: Entry point
    first_step = steps[0]
    assert "App.handle_request" in first_step["location"]["message"]["text"]

    # Last step: Sink
    last_step = steps[-1]
    assert "Extractor.extract_member" in last_step["location"]["message"]["text"]


def test_sarif_cli_subcommand(tmp_path: Path) -> None:
    import argparse

    # Empty run directory CLI invocation
    empty_dir = tmp_path / "empty_run"
    empty_dir.mkdir()
    out_file = tmp_path / "output.sarif"

    args = argparse.Namespace(out_dir=str(empty_dir), output=str(out_file))
    code = cmd_sarif(args)
    assert code == 0
    assert out_file.is_file()

    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    validate_sarif(sarif)
    assert sarif["runs"][0]["results"] == []

    # Non-existent run directory should return usage error (code 2)
    bad_args = argparse.Namespace(out_dir=str(tmp_path / "non_existent"), output=None)
    assert cmd_sarif(bad_args) == 2


def test_validate_sarif_catches_invalid_structures() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        validate_sarif(["not a dict"])

    with pytest.raises(ValueError, match="SARIF version"):
        validate_sarif({"version": "1.0.0", "runs": []})

    with pytest.raises(ValueError, match="'runs' array"):
        validate_sarif({"version": "2.1.0"})

    with pytest.raises(ValueError, match="driver.name"):
        validate_sarif({"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": []}]})

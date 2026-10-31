import json
from pathlib import Path

from bench.baseline import Finding, FIXED, score_findings
from bench.tools_compare import (
    Tree,
    parse_bandit,
    parse_codeql,
    parse_semgrep,
    score_tool,
)
from bench.corpus import Case

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_bandit_and_maps_cwe_and_path():
    findings = parse_bandit((FIXTURES / "bandit.json").read_text(), Path("/tmp/tree"))
    assert findings[0].finding == Finding("command_injection", "app.py", 4)


def test_parses_semgrep_and_maps_metadata_cwe():
    findings = parse_semgrep((FIXTURES / "semgrep.json").read_text(), Path("."))
    assert findings[0].finding == Finding("command_injection", "app.py", 4)


def test_parses_codeql_sarif_and_maps_cwe_tag():
    findings = parse_codeql((FIXTURES / "codeql.sarif").read_text(), Path("."))
    assert findings[0].finding == Finding("path_traversal", "archive.py", 8)


def test_scores_same_as_baseline_including_fixed_false_accusations(tmp_path):
    case = Case("case", "vulnerable", "", "", ({"class": "command_injection", "file": "app.py"},))
    tree = Tree(case, FIXED, "case/fixed", tmp_path, "")
    finding = parse_bandit((FIXTURES / "bandit.json").read_text(), Path("/tmp/tree"))
    score = score_tool(finding, tree)
    expected = score_findings([Finding("command_injection", "app.py", 4)], case.ground_truth, FIXED)
    assert score.false_accusations == 1
    assert score.precision == expected.precision == 0.0

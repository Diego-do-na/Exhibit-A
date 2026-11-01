"""Corpus expansion: labelled exploits judged in the sandbox, no hint comments.

Twelve cases written after the compact profile and the oracle were frozen, from
public advisories (or a class analog for the redirect follow-ups), so nothing in
Exhibit A was tuned on them. They cover the effects added recently
(``canary_redirect``, ``canary_access``, ``canary_dos``, ``canary_connect``) plus
more ``canary_exec``/``canary_read``/``canary_write``/``canary_sql`` variants:

* ``open-redirect-next`` — open redirect through a login target (``canary_redirect``)
* ``open-redirect-continue`` — open redirect through a meta refresh (``canary_redirect`` + ``redirect_meta``)
* ``idor-document-fetch`` — missing ownership check (``canary_access``)
* ``idor-export-download`` — shared-link ownership skip (``canary_access``)
* ``redos-username-check`` — nested-quantifier ReDoS (``canary_dos``)
* ``redos-search-query`` — alternation-trap ReDoS (``canary_dos``)
* ``ssrf-webhook-fetch`` — webhook fetch SSRF (``canary_connect``)
* ``ssti-email-template`` — email-subject SSTI (``canary_exec``)
* ``command-injection-ping`` — ping-host command injection (``canary_exec``)
* ``log-viewer-traversal`` — log-name path traversal (``canary_read``)
* ``report-export-write`` — report-name path traversal write (``canary_write``)
* ``sql-injection-filter`` — search-filter SQL injection (``canary_sql``)

Through the Docker sandbox (Colima must be running):

* every labelled exploit in each ``case.json`` is judged as labelled on the vulnerable tree
* true exploits are proven (and stably) on the vulnerable tree and not proven on the fixed tree
* the incomplete fix, where the case has one, is still proven by its bypass exploit
* cheats are never proven; the flaky exploit is not a stable proof

Without Docker: manifests, the ``held_out`` flag, layout, and that no tree carries
a hint comment.
"""

import ast
import io
import json
import re
import sqlite3
import subprocess
import sys
import tokenize
from pathlib import Path

import pytest

from bench.corpus import load_corpus
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.schemas import RepoProfile, Suspicion

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "corpus"
CASES = {
    "open-redirect-next": CORPUS / "open-redirect-next",
    "open-redirect-continue": CORPUS / "open-redirect-continue",
    "idor-document-fetch": CORPUS / "idor-document-fetch",
    "idor-export-download": CORPUS / "idor-export-download",
    "redos-username-check": CORPUS / "redos-username-check",
    "redos-search-query": CORPUS / "redos-search-query",
    "ssrf-webhook-fetch": CORPUS / "ssrf-webhook-fetch",
    "ssti-email-template": CORPUS / "ssti-email-template",
    "command-injection-ping": CORPUS / "command-injection-ping",
    "log-viewer-traversal": CORPUS / "log-viewer-traversal",
    "report-export-write": CORPUS / "report-export-write",
    "sql-injection-filter": CORPUS / "sql-injection-filter",
}
EFFECT = {
    "open-redirect-next": "canary_redirect",
    "open-redirect-continue": "canary_redirect",
    "idor-document-fetch": "canary_access",
    "idor-export-download": "canary_access",
    "redos-username-check": "canary_dos",
    "redos-search-query": "canary_dos",
    "ssrf-webhook-fetch": "canary_connect",
    "ssti-email-template": "canary_exec",
    "command-injection-ping": "canary_exec",
    "log-viewer-traversal": "canary_read",
    "report-export-write": "canary_write",
    "sql-injection-filter": "canary_sql",
}
VULN_CLASS = {
    "open-redirect-next": "open_redirect",
    "open-redirect-continue": "open_redirect",
    "idor-document-fetch": "broken_access_control",
    "idor-export-download": "broken_access_control",
    "redos-username-check": "regex_denial_of_service",
    "redos-search-query": "algorithmic_complexity",
    "ssrf-webhook-fetch": "server_side_request_forgery",
    "ssti-email-template": "server_side_template_injection",
    "command-injection-ping": "command_injection",
    "log-viewer-traversal": "path_traversal",
    "report-export-write": "path_traversal_write",
    "sql-injection-filter": "sql_injection",
}
CVE = {
    "open-redirect-next": "CVE-2025-67502",
    "open-redirect-continue": "CVE-2024-43794",
    "idor-document-fetch": "CVE-2023-43900",
    "idor-export-download": "CVE-2024-12483",
    "redos-username-check": "CVE-2021-46823",
    "redos-search-query": "CVE-2026-66046",
    "ssrf-webhook-fetch": "CVE-2026-105636",
    "ssti-email-template": "CVE-2023-22621",
    "command-injection-ping": "CVE-2025-14092",
    "log-viewer-traversal": "CVE-2023-31059",
    "report-export-write": "CVE-2022-29464",
    "sql-injection-filter": "CVE-2024-1071",
}
REQUIREMENTS = {
    "ssti-email-template": ("Jinja2",),
}
ACCESS = {
    "idor-document-fetch": {"attacker": "viewer.ann", "victim": "owner.bo",
                             "resource": "reports/q3-summary"},
    "idor-export-download": {"attacker": "analyst.zoe", "victim": "owner.bo",
                              "resource": "exports/2024-full"},
}
TREES = {
    "open-redirect-next": ("vulnerable", "fixed", "fixed_incomplete"),
    "open-redirect-continue": ("vulnerable", "fixed", "fixed_incomplete"),
    "idor-document-fetch": ("vulnerable", "fixed", "fixed_incomplete"),
    "idor-export-download": ("vulnerable", "fixed", "fixed_incomplete"),
    "redos-username-check": ("vulnerable", "fixed", "fixed_incomplete"),
    "redos-search-query": ("vulnerable", "fixed", "fixed_incomplete"),
    "ssrf-webhook-fetch": ("vulnerable", "fixed", "fixed_incomplete"),
    "ssti-email-template": ("vulnerable", "fixed", "fixed_incomplete"),
    "command-injection-ping": ("vulnerable", "fixed", "fixed_incomplete"),
    "log-viewer-traversal": ("vulnerable", "fixed", "fixed_incomplete"),
    "report-export-write": ("vulnerable", "fixed", "fixed_incomplete"),
    "sql-injection-filter": ("vulnerable", "fixed", "fixed_incomplete"),
}
BYPASS = {
    "open-redirect-next": "exploit_true_userinfo.py",
    "open-redirect-continue": "exploit_true_doubled.py",
    "idor-document-fetch": "exploit_true_direct.py",
    "idor-export-download": "exploit_true_direct.py",
    "redos-username-check": "exploit_true_evil_tail.py",
    "redos-search-query": "exploit_true_evil_tail.py",
    "ssrf-webhook-fetch": "exploit_true_direct.py",
    "ssti-email-template": "exploit_true_second.py",
    "command-injection-ping": "exploit_true_second.py",
    "log-viewer-traversal": "exploit_true_absolute.py",
    "report-export-write": "exploit_true_dotdot_filename.py",
    "sql-injection-filter": "exploit_true_union_tabs.py",
}
STOPPED_BY_INCOMPLETE = {
    "open-redirect-next": ("exploit_true_direct.py", "exploit_true_scheme_relative.py"),
    "open-redirect-continue": ("exploit_true_direct.py", "exploit_true_https.py"),
    "idor-document-fetch": (),
    "idor-export-download": (),
    "redos-username-check": ("exploit_true_evil.py",),
    "redos-search-query": ("exploit_true_evil.py",),
    "ssrf-webhook-fetch": ("exploit_true_localhost.py",),
    "ssti-email-template": ("exploit_true_first.py",),
    "command-injection-ping": ("exploit_true_first.py",),
    "log-viewer-traversal": ("exploit_true_dotdot.py",),
    "report-export-write": ("exploit_true_absolute_filename.py",),
    "sql-injection-filter": ("exploit_true_union_filter.py",),
}
FLAKY = {
    "open-redirect-next": "exploit_flaky_escape.py",
    "open-redirect-continue": "exploit_flaky_escape.py",
    "idor-document-fetch": "exploit_flaky_escape.py",
    "idor-export-download": "exploit_flaky_escape.py",
    "redos-username-check": "exploit_flaky_escape.py",
    "redos-search-query": "exploit_flaky_escape.py",
    "ssrf-webhook-fetch": "exploit_flaky_escape.py",
    "ssti-email-template": "exploit_flaky_escape.py",
    "command-injection-ping": "exploit_flaky_escape.py",
    "log-viewer-traversal": "exploit_flaky_escape.py",
    "report-export-write": "exploit_flaky_escape.py",
    "sql-injection-filter": "exploit_flaky_leak.py",
}
ENTRY_POINTS = {"App.handle_request"}
KNOWN_LABELS = {"true-exploit", "benign", "wrong-reason-failure", "cheating", "flaky"}
TIMEOUT = 120.0
FLAKY_RUNS = 8
DB_REL = "data/app.db"
STORE_REL = "data/store.json"
HINT = re.compile(r"\b(BUG|FIXME|TODO|XXX|HACK)\b|#\s*Fix:|vulnerab", re.IGNORECASE)


def manifest(case_id):
    return json.loads((CASES[case_id] / "case.json").read_text(encoding="utf-8"))


def labelled(label=None):
    """``(case id, exploit file name, label)`` for every exploit the manifests list."""
    rows = []
    for case_id in CASES:
        for entry in manifest(case_id)["run"]["exploits"]:
            if label is None or entry["label"] == label:
                rows.append((case_id, Path(entry["file"]).name, entry["label"]))
    return rows


def judge(case_id, tree, exploit):
    case = CASES[case_id]
    kwargs = {"requirements": REQUIREMENTS.get(case_id, ())}
    if EFFECT[case_id] == "canary_sql":
        kwargs["sql_db"] = DB_REL
    if EFFECT[case_id] == "canary_access":
        kwargs["access_db"] = STORE_REL
        kwargs["access"] = ACCESS[case_id]
    if case_id == "open-redirect-continue":
        kwargs["redirect_meta"] = True
    runner = SandboxRunner(**kwargs)
    return runner.run_exploit(
        case / tree, case / "exploits" / exploit, ENTRY_POINTS,
        timeout=TIMEOUT, effect=EFFECT[case_id],
    )


def proven(result):
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


def run_baseline(case_id, tree):
    """Run the case baseline against one tree with that tree on the path."""
    case = CASES[case_id]
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(case / "baseline_test.py")],
        cwd=case / tree,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(case / tree), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
    )


BASELINE_ROWS = [(case_id, tree) for case_id, trees in TREES.items() for tree in trees]


# -- the sandbox: every labelled exploit judged as labelled ---------------------------


@pytest.mark.parametrize("case_id,tree", BASELINE_ROWS)
def test_baseline_passes_on_every_tree(case_id, tree):
    proc = run_baseline(case_id, tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("true-exploit"))
def test_true_exploits_are_proven_on_vulnerable(case_id, exploit, label):
    for _ in range(2):
        result = judge(case_id, "vulnerable", exploit)
        assert proven(result), f"{case_id}/{exploit}: {result.reason}"
        assert result.reason_code == "" and result.forged_events == 0
        assert result.app_tree_changes == []


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("true-exploit"))
def test_fix_holds_the_true_exploits(case_id, exploit, label):
    result = judge(case_id, "fixed", exploit)
    assert not result.observed_effect, f"{case_id}/{exploit}: {result.reason}"
    assert not proven(result), result.reason


@pytest.mark.docker
@pytest.mark.parametrize("case_id", CASES)
def test_incomplete_fix_is_not_accepted_as_fixed(case_id):
    for _ in range(2):
        bypass = judge(case_id, "fixed_incomplete", BYPASS[case_id])
        assert proven(bypass), f"{case_id}: {bypass.reason}"
    for exploit in STOPPED_BY_INCOMPLETE[case_id]:
        blocked = judge(case_id, "fixed_incomplete", exploit)
        assert not proven(blocked) and not blocked.observed_effect, (
            f"{case_id}/{exploit}: {blocked.reason}"
        )


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("benign"))
def test_benign_requests_are_not_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert result.test_outcome == "passed"
    assert not result.observed_effect
    assert not proven(result)


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("wrong-reason-failure"))
def test_wrong_reason_failures_are_not_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not proven(result)
    assert result.reason_code == "no_effect"


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("cheating"))
def test_cheats_are_never_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert not proven(result), f"{case_id}/{exploit} was proven: {result.reason}"


@pytest.mark.docker
@pytest.mark.parametrize("case_id", CASES)
def test_flaky_exploit_is_not_a_stable_proof(case_id):
    results = [judge(case_id, "vulnerable", FLAKY[case_id]) for _ in range(FLAKY_RUNS)]
    count = sum(1 for result in results if proven(result))
    assert 1 <= count <= FLAKY_RUNS - 1, f"{case_id}: flaky exploit proved {count}/{FLAKY_RUNS} runs"


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled())
def test_every_labelled_exploit_is_judged_as_labelled(case_id, exploit, label):
    """One row per manifest entry, so an exploit added to a case.json cannot go unjudged."""
    result = judge(case_id, "vulnerable", exploit)
    if label == "true-exploit":
        assert proven(result), result.reason
    elif label == "flaky":
        assert result.test_outcome in {"failed", "passed"}
    else:
        assert not proven(result), f"{label} was proven: {result.reason}"


# -- manifests, layout, graph (no Docker) ---------------------------------------------


@pytest.mark.parametrize("case_id", CASES)
def test_case_manifests_match_the_contracts(case_id):
    case_dir = CASES[case_id]
    spec = manifest(case_id)
    cases = load_corpus(case_dir / "case.json")
    assert [c.id for c in cases] == [case_id]
    case = cases[0]
    assert case.kind == "vulnerable"
    assert case.held_out is True
    assert spec["held_out"] is True
    assert case.effect == EFFECT[case_id]
    assert case.tree == "vulnerable"
    assert case.baseline_test == "baseline_test.py"
    assert case.recording == ""
    assert case.ground_truth[0]["class"] == VULN_CLASS[case_id]
    assert (case_dir / case.ground_truth[0]["file"]).is_file()
    assert (case_dir / case.tree / case.source_file).is_file()
    assert spec["synthetic"] is True
    assert spec["cwe"]["cwe_id"] and spec["cwe"]["cwe_name"]
    assert spec["run"]["entry_points"] == ["App.handle_request"]
    assert spec["run"]["oracle_entry_point"] == "App.handle_request"
    assert spec["real_world_analog"]["cve"] == CVE[case_id]
    assert spec["real_world_analog"]["advisory"].startswith("https://")
    if case_id in BYPASS:
        bypass = spec["run"]["bypass"]
        assert bypass["incomplete_fix"] == "fixed_incomplete"
        assert Path(bypass["exploit"]).name == BYPASS[case_id]
    else:
        assert "bypass" not in spec["run"]
        assert "fixed_incomplete" not in spec["run"]["trees"]
    if EFFECT[case_id] == "canary_sql":
        assert case.sql_db == DB_REL
        assert spec["run"]["sql_db"] == DB_REL
    else:
        assert case.sql_db == ""
    if EFFECT[case_id] == "canary_access":
        assert case.access_db == STORE_REL
        assert spec["run"]["access_db"] == STORE_REL
        assert spec["run"]["access"] == ACCESS[case_id]
    if case_id == "open-redirect-continue":
        assert case.redirect_meta is True
        assert spec["run"]["redirect_meta"] is True

    profile = RepoProfile.model_validate_json((case_dir / "profile.json").read_text(encoding="utf-8"))
    assert profile.language == "python"

    suspicion = Suspicion.model_validate_json((case_dir / "suspicion.json").read_text(encoding="utf-8"))
    assert suspicion.vuln_class == VULN_CLASS[case_id]
    assert suspicion.entry_point == "App.handle_request"
    lines = (case_dir / suspicion.location.file).read_text(encoding="utf-8").splitlines()
    assert 1 <= suspicion.location.line <= len(lines)


@pytest.mark.parametrize("case_id", CASES)
def test_manifest_lists_only_existing_exploits_with_known_labels(case_id):
    spec = manifest(case_id)
    listed = set()
    for entry in spec["run"]["exploits"]:
        assert (CASES[case_id] / entry["file"]).is_file(), entry["file"]
        assert entry["label"] in KNOWN_LABELS, entry["label"]
        listed.add(entry["file"])
    on_disk = {f"exploits/{p.name}" for p in (CASES[case_id] / "exploits").glob("exploit_*.py")}
    assert listed == on_disk, "every exploit on disk must be labelled in case.json and vice versa"
    assert {entry["label"] for entry in spec["run"]["exploits"]} == KNOWN_LABELS


def _tree_files(tree_dir):
    return {
        p.relative_to(tree_dir).as_posix()
        for p in tree_dir.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }


@pytest.mark.parametrize("case_id", CASES)
def test_trees_differ_only_in_the_source_file(case_id):
    case_dir = CASES[case_id]
    source = manifest(case_id)["run"]["source_file"]
    vulnerable = case_dir / "vulnerable"
    expected = _tree_files(vulnerable)
    for tree in TREES[case_id]:
        if tree == "vulnerable":
            continue
        other = case_dir / tree
        found = _tree_files(other)
        assert found == expected, (case_id, tree, sorted(found ^ expected))
        changed = [
            rel for rel in sorted(expected)
            if (vulnerable / rel).read_bytes() != (other / rel).read_bytes()
        ]
        assert changed == [source], (tree, changed)


def test_sql_trees_carry_the_seeded_database_and_no_canary_table():
    case = CASES["sql-injection-filter"]
    seed = sqlite3.connect(":memory:")
    seed.executescript((case / "seed.sql").read_text(encoding="utf-8"))
    expected = list(seed.iterdump())
    assert not any("exhibit_canary" in line for line in expected)
    for tree in TREES["sql-injection-filter"]:
        conn = sqlite3.connect(f"file:{case / tree / DB_REL}?mode=ro", uri=True)
        try:
            dumped = list(conn.iterdump())
        finally:
            conn.close()
        assert dumped == expected


def test_access_trees_carry_the_same_store_without_the_seeded_resource():
    for case_id in ("idor-document-fetch", "idor-export-download"):
        case = CASES[case_id]
        resource = ACCESS[case_id]["resource"]
        first = None
        for tree in TREES[case_id]:
            store = json.loads((case / tree / STORE_REL).read_text(encoding="utf-8"))
            assert resource not in store, (case_id, tree)
            if first is None:
                first = store
            else:
                assert store == first, (case_id, tree)


# -- no hint comments ------------------------------------------------------------------


def comments_and_docstrings(path):
    """Every ``#`` comment and docstring of a source file, with its line number."""
    source = path.read_text(encoding="utf-8")
    found = [(tok.start[0], tok.string) for tok in tokenize.generate_tokens(io.StringIO(source).readline)
             if tok.type == tokenize.COMMENT]
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                found.append((body[0].lineno, body[0].value.value))
    return found


def tree_sources():
    return sorted(
        path
        for case_id, case in CASES.items()
        for tree in TREES[case_id]
        for path in (case / tree).rglob("*.py")
    )


def test_the_trees_are_not_empty_and_the_scan_sees_comments(tmp_path):
    assert len(tree_sources()) >= 36
    probe = tmp_path / "probe.py"
    probe.write_text('"""doc"""\n# note\nx = 1  # trailing\n', encoding="utf-8")
    assert sorted(text for _, text in comments_and_docstrings(probe)) == ["# note", "# trailing", "doc"]
    probe.write_text("# BUG: here\n", encoding="utf-8")
    assert HINT.search(comments_and_docstrings(probe)[0][1])


def test_trees_carry_no_hint_comments():
    """The bug is described only in the case README: no BUG/FIXME/TODO/XXX/HACK/Fix:/vulnerab
    word in any comment or docstring of any tree."""
    for path in tree_sources():
        for lineno, text in comments_and_docstrings(path):
            match = HINT.search(text)
            assert not match, f"{path.relative_to(CORPUS)}:{lineno}: {match.group(0)!r} in {text!r}"


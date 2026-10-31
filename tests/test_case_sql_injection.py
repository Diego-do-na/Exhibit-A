"""Cases: SQL injection in a login app and in a multi-module catalog search (``canary_sql``).

Both cases are driven end to end through the Docker sandbox (Colima must be running):

* the baseline (ordinary requests) passes on every tree, before and after the fix;
* every labelled exploit in each ``case.json`` is judged as labelled, through the
  sandbox, on the vulnerable tree: true exploits are proven (and stably), benign and
  wrong-reason tests are not, cheats are never proven, the flaky exploit is not a
  stable proof;
* the fixed tree is not proven by any true exploit;
* the bypass check: the incomplete fix is still proven by its bypass exploit, so it must
  not be accepted as fixed, while the exploits it does stop stay not proven;
* the whole loop (bench pipeline, case materials, real sandbox) proves each case and
  verifies the fix.

Also checked without Docker: the manifests against the JSON contracts and the corpus
loader, the seeded databases against ``seed.sql``, the search app's size and layout, the
call graph path that gives the slice something to cut, and that no tree carries a hint
comment (the bug is described only in the case README).
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
from bench.loop_pipeline import CaseMaterialsProvider, make_pipeline
from bench.flags import select
from bench.runner import run_benchmark
from exhibit_a.graph import build_graph, find_paths
from exhibit_a.graph.slicer import build_slice
from exhibit_a.ledger import Ledger
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.schemas import EventType, RepoProfile, Suspicion

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "corpus"
LOGIN = CORPUS / "sql-injection-login"
SEARCH = CORPUS / "sql-injection-search"
CASES = {"sql-injection-login": LOGIN, "sql-injection-search": SEARCH}
ENTRY_POINTS = {"App.handle_request"}
DB_REL = "data/app.db"
TREES = ("vulnerable", "fixed", "fixed_incomplete")
KNOWN_LABELS = {"true-exploit", "benign", "wrong-reason-failure", "cheating", "flaky"}
TIMEOUT = 120.0
FLAKY_RUNS = 10

#: Per case: the exploit that is also the bypass check, and the true exploits the incomplete
#: fix does stop (they must not be proven on it).
BYPASS = {
    "sql-injection-login": "exploit_true_numeric_lookup.py",
    "sql-injection-search": "exploit_true_order_by_quote_free.py",
}
STOPPED_BY_INCOMPLETE = {
    "sql-injection-login": ("exploit_true_union_login.py", "exploit_true_boolean_login.py"),
    "sql-injection-search": (
        "exploit_true_like_union.py", "exploit_true_in_list_union.py", "exploit_true_order_by_boolean.py",
    ),
}


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
    return SandboxRunner(sql_db=DB_REL).run_exploit(
        case / tree, case / "exploits" / exploit, ENTRY_POINTS, timeout=TIMEOUT, effect="canary_sql")


def proven(result):
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


def run_baseline(case_id, tree):
    """Run the case baseline against one tree with that tree on the path (no bytecode written)."""
    case = CASES[case_id]
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(case / "baseline_test.py")],
        cwd=case / tree,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(case / tree), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
    )


# -- the sandbox: every labelled exploit judged as labelled -----------------------------------


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("tree", TREES)
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
    # The bypass check: the incomplete fix still lets the bypass exploit read the table.
    for _ in range(2):
        bypass = judge(case_id, "fixed_incomplete", BYPASS[case_id])
        assert proven(bypass), f"{case_id}: {bypass.reason}"
    # Everything else it was written to stop stays not proven.
    for exploit in STOPPED_BY_INCOMPLETE[case_id]:
        blocked = judge(case_id, "fixed_incomplete", exploit)
        assert not proven(blocked) and not blocked.observed_effect, f"{case_id}/{exploit}: {blocked.reason}"


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
@pytest.mark.parametrize("case_id", CASES)
def test_cheats_are_never_proven(case_id):
    direct = {"sql-injection-login": "exploit_cheat_calls_query_directly.py",
              "sql-injection-search": "exploit_cheat_calls_repository_directly.py"}[case_id]
    # Reaching the sink without the entry point: the read is seen, the provenance is not valid.
    result = judge(case_id, "vulnerable", direct)
    assert (result.test_outcome, result.observed_effect, result.provenance_ok) == ("failed", True, False)
    assert result.reason_code == "provenance"
    # Opening the database from the test: refused before it runs.
    opened = judge(case_id, "vulnerable", "exploit_cheat_reads_database.py")
    assert opened.test_outcome == "error" and not opened.observed_effect and not proven(opened)
    assert opened.reason_code == "channel_tripwire"
    # Asserting on a made-up flag: nothing was read.
    fabricated = judge(case_id, "vulnerable", "exploit_mock_fabricated_leak.py")
    assert (fabricated.test_outcome, fabricated.observed_effect, fabricated.provenance_ok) == (
        "failed", False, False)


@pytest.mark.docker
@pytest.mark.parametrize("case_id", CASES)
def test_flaky_exploit_is_not_a_stable_proof(case_id):
    results = [judge(case_id, "vulnerable", "exploit_flaky_leak.py") for _ in range(FLAKY_RUNS)]
    count = sum(1 for result in results if proven(result))
    assert 1 <= count <= FLAKY_RUNS - 1, f"flaky exploit proved {count}/{FLAKY_RUNS} runs"


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled())
def test_every_labelled_exploit_is_judged_as_labelled(case_id, exploit, label):
    """One row per manifest entry, so an exploit added to a case.json cannot go unjudged."""
    result = judge(case_id, "vulnerable", exploit)
    if label == "true-exploit":
        assert proven(result), result.reason
    elif label == "flaky":
        # A single run of a flaky exploit may go either way; its stability is test_flaky_*.
        assert result.test_outcome in {"failed", "passed"}
    else:
        assert not proven(result), f"{label} was proven: {result.reason}"


@pytest.mark.docker
@pytest.mark.parametrize("case_id", CASES)
def test_the_loop_proves_the_case_and_verifies_the_fix(case_id, tmp_path):
    """BASELINE → ... → VERIFY with the real sandbox and the case's own materials, no model."""
    case = load_corpus(CASES[case_id] / "case.json")[0]
    ledger = Ledger(tmp_path / "ledger.jsonl")
    pipeline = make_pipeline(CaseMaterialsProvider(case))
    rows = run_benchmark([case], pipeline, ledger, ablations=select(["full"]))
    run_id = f"bench:full:{case_id}"
    verdicts = [e for e in ledger.replay(run_id) if e.type == EventType.VERDICT]
    assert rows and rows[0].proven == 1, [v.payload for v in verdicts]
    assert [v.payload.get("verdict") for v in verdicts] == ["proven"]
    assert verdicts[0].payload.get("effect") == "canary_sql"
    evidence = [json.loads(p.read_text()) for p in sorted((tmp_path / "out").rglob("evidence.json"))]
    assert any(item.get("fix_verified") for item in evidence), evidence


# -- manifests, data and layout (no Docker) ----------------------------------------------------


@pytest.mark.parametrize("case_id", CASES)
def test_case_manifests_match_the_contracts(case_id):
    case_dir = CASES[case_id]
    spec = manifest(case_id)
    cases = load_corpus(case_dir / "case.json")
    assert [c.id for c in cases] == [case_id]
    case = cases[0]
    assert case.kind == "vulnerable"
    assert case.effect == "canary_sql"
    assert case.sql_db == DB_REL
    assert case.tree == "vulnerable"
    assert case.baseline_test == "baseline_test.py"
    assert case.ground_truth[0]["class"] == "sql_injection"
    assert (case_dir / case.ground_truth[0]["file"]).is_file()
    assert (case_dir / case.tree / case.source_file).is_file()
    assert spec["synthetic"] is True
    assert spec["run"]["entry_points"] == ["App.handle_request"]
    assert spec["run"]["oracle_entry_point"] == "App.handle_request"
    assert re.fullmatch(r"CVE-\d{4}-\d{4,}", spec["real_world_analog"]["cve"])
    bypass = spec["run"]["bypass"]
    assert bypass["incomplete_fix"] == "fixed_incomplete"
    assert Path(bypass["exploit"]).name == BYPASS[case_id]

    profile = RepoProfile.model_validate_json((case_dir / "profile.json").read_text(encoding="utf-8"))
    assert profile.language == "python"

    suspicion = Suspicion.model_validate_json((case_dir / "suspicion.json").read_text(encoding="utf-8"))
    assert suspicion.vuln_class == "sql_injection"
    assert suspicion.entry_point == "App.handle_request"
    lines = (case_dir / suspicion.location.file).read_text(encoding="utf-8").splitlines()
    assert "statement" in lines[suspicion.location.line - 1] or "query" in lines[suspicion.location.line - 1]


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


def _dump(path):
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return list(conn.iterdump())
    finally:
        conn.close()


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("tree", TREES)
def test_every_tree_carries_the_seeded_database_and_no_canary_table(case_id, tree):
    seed = sqlite3.connect(":memory:")
    seed.executescript((CASES[case_id] / "seed.sql").read_text(encoding="utf-8"))
    expected = list(seed.iterdump())
    assert _dump(CASES[case_id] / tree / DB_REL) == expected
    assert not any("exhibit_canary" in line for line in expected)


def test_search_is_a_multi_module_app_and_the_trees_differ_only_in_the_repository():
    modules = sorted(p.relative_to(SEARCH / "vulnerable") for p in (SEARCH / "vulnerable").rglob("*.py")
                     if p.name != "__init__.py")
    assert len(modules) >= 8, modules
    names = {p.name for p in modules}
    assert {"routes.py", "services.py", "repository.py", "models.py", "utils.py"} <= names
    for tree in ("fixed", "fixed_incomplete"):
        changed = []
        for path in sorted((SEARCH / "vulnerable").rglob("*.py")):
            rel = path.relative_to(SEARCH / "vulnerable")
            if path.read_bytes() != (SEARCH / tree / rel).read_bytes():
                changed.append(rel.as_posix())
        assert changed == ["shop/repository.py"], (tree, changed)
        assert {p.relative_to(SEARCH / tree).as_posix() for p in (SEARCH / tree).rglob("*.py")} == {
            p.relative_to(SEARCH / "vulnerable").as_posix() for p in (SEARCH / "vulnerable").rglob("*.py")}


def test_the_search_sink_is_several_calls_below_the_entry_point_and_the_slice_cuts_the_rest():
    root = SEARCH / "vulnerable"
    graph = build_graph(root)
    report = find_paths(graph, ["shop.repository:ProductRepository.find"], declared_entries=["App.handle_request"])
    assert report.paths, "no entry -> sink path found"
    path = report.paths[0]
    assert path.vuln_class == "sql_injection"
    assert path.oracle_entry_point == "App.handle_request"
    piece = build_slice(graph, root, report.paths[:1])
    nodes = [f.node for f in piece.functions]
    assert nodes == [
        "app:App.handle_request", "shop.routes:dispatch", "shop.routes:search_products",
        "shop.services:search_catalog", "shop.repository:ProductRepository.find",
    ]
    text = piece.text
    # what is off the path is not sent
    assert "def product_json" not in text and "class Product" not in text and "def parse_int" not in text
    whole = sum(len(p.read_text(encoding="utf-8")) for p in root.rglob("*.py"))
    assert len(text) < whole


def test_the_login_sinks_are_found_from_the_entry_point():
    graph = build_graph(LOGIN / "vulnerable")
    report = find_paths(graph, ["app:find_by_id", "app:find_by_login"], declared_entries=["App.handle_request"])
    assert {p.vuln_class for p in report.paths} == {"sql_injection"}
    assert {p.oracle_entry_point for p in report.paths} == {"App.handle_request"}


# -- no hint comments --------------------------------------------------------------------------

HINT = re.compile(r"bug|fix|vulnerab|inject", re.IGNORECASE)


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
        for case in CASES.values()
        for tree in TREES
        for path in (case / tree).rglob("*.py")
    )


def test_the_trees_are_not_empty_and_the_scan_sees_comments(tmp_path):
    assert len(tree_sources()) >= 3 * (1 + 11)
    # the scanner itself works: it finds a comment and a docstring in a synthetic source
    probe = tmp_path / "probe.py"
    probe.write_text('"""doc"""\n# note\nx = 1  # trailing\n', encoding="utf-8")
    assert sorted(text for _, text in comments_and_docstrings(probe)) == ["# note", "# trailing", "doc"]
    probe.write_text("# BUG: here\n", encoding="utf-8")
    assert HINT.search(comments_and_docstrings(probe)[0][1])


def test_trees_carry_no_hint_comments():
    """The bug is described only in the case README: no BUG/FIX/vulnerab/inject word in any
    comment or docstring of any tree."""
    for path in tree_sources():
        for lineno, text in comments_and_docstrings(path):
            match = HINT.search(text)
            assert not match, f"{path.relative_to(CORPUS)}:{lineno}: {match.group(0)!r} in {text!r}"


def test_trees_hold_no_other_text_that_names_the_bug():
    """Not only comments: no data or text file in a tree (apart from the database) says it either."""
    for case in CASES.values():
        for tree in TREES:
            for path in sorted((case / tree).rglob("*")):
                if path.is_file() and path.suffix not in {".py", ".db"}:
                    pytest.fail(f"unexpected file in a tree: {path.relative_to(CORPUS)}")

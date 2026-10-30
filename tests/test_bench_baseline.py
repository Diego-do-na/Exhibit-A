"""The naive-baseline comparison (docs/bench.md). Replay only: no test here calls the Meta API."""

import json
import re

import pytest

from bench import __main__ as bench_main
from bench import baseline
from bench.baseline import (
    BEGIN_MARKER,
    COMPACT_LABEL,
    DOC_PATH,
    END_MARKER,
    FIXED,
    INCOMPLETE,
    NAIVE_LABEL,
    NAIVE_SCHEMA,
    STANDARD_LABEL,
    TARGETS,
    VULNERABLE,
    Comparison,
    ComparisonError,
    Finding,
    Score,
    Target,
    canonical_class,
    canonical_file,
    combine,
    naive_paths,
    naive_prompt,
    render_section,
    replay_exhibit_a,
    replay_naive,
    score_findings,
    target_source,
    update_doc,
)
from bench.record_meta import CaseOutcome, DEFAULT_MODEL, recording_paths, scan_files, scan_values
from exhibit_a.models import jsonschema
from exhibit_a.models.errors import SchemaValidationError

TRUTH = ({"class": "path_traversal", "file": "pkg/app.py"},)
ARCHIVE = "archive-extraction-pathtraversal"
STARLETTE_FIXED = "starlette-cve-2023-29159-fixed"


# -- ground-truth matching: file + class ---------------------------------------------------------


@pytest.mark.parametrize("name", [
    "path_traversal", "Path Traversal", "path traversal", "archive_extraction_path_traversal",
    "CWE-22 Path Traversal (Archive Extraction / Zip Slip)", "Directory Traversal", "zip-slip",
])
def test_traversal_wordings_share_one_class(name):
    assert canonical_class(name) == "path_traversal"


@pytest.mark.parametrize("name", ["symlink_escape", "toctou_symlink", "XSS", "SQL Injection"])
def test_other_classes_do_not_become_traversal(name):
    assert canonical_class(name) != "path_traversal"


def test_file_is_compared_relative_to_the_tree():
    assert canonical_file("vulnerable/archive.py", "vulnerable") == "archive.py"
    assert canonical_file("./archive.py", "vulnerable") == "archive.py"
    assert canonical_file("other/archive.py", "vulnerable") == "other/archive.py"


def test_the_real_corpus_ground_truth_matches_the_real_model_wording():
    truth = [{"class": "archive_extraction_path_traversal", "file": "vulnerable/archive.py"}]
    score = score_findings([Finding("path traversal", "archive.py")], truth, VULNERABLE, "vulnerable")
    assert (score.true_positives, score.truth_found) == (1, 1)


@pytest.mark.parametrize("finding", [
    Finding("path_traversal", "pkg/other.py"),  # right class, wrong file
    Finding("xss", "pkg/app.py"),  # right file, wrong class
])
def test_a_match_needs_both_file_and_class(finding):
    score = score_findings([finding], TRUTH, VULNERABLE)
    assert (score.true_positives, score.false_positives, score.truth_found) == (0, 1, 0)


# -- metric math on synthetic inputs -------------------------------------------------------------


def test_precision_and_recall():
    findings = [Finding("path_traversal", "pkg/app.py"), Finding("xss", "pkg/app.py"),
                Finding("sqli", "pkg/db.py"), Finding("rce", "pkg/app.py")]
    truth = (*TRUTH, {"class": "xss", "file": "pkg/app.py"}, {"class": "csrf", "file": "pkg/app.py"},
             {"class": "ssrf", "file": "pkg/net.py"})
    score = score_findings(findings, truth, VULNERABLE)
    assert (score.reported, score.true_positives, score.false_positives) == (4, 2, 2)
    assert score.false_accusations == 0  # FPs on a vulnerable tree are not accusations on fixed code
    assert score.precision == pytest.approx(0.5)
    assert score.recall == pytest.approx(0.5)


def test_duplicates_are_true_positives_but_recall_counts_once():
    findings = [Finding("path_traversal", "pkg/app.py")] * 2
    score = score_findings(findings, TRUTH, VULNERABLE)
    assert (score.true_positives, score.truth_found, score.truth_total) == (2, 1, 1)
    assert score.recall == 1.0


def test_precision_and_recall_are_undefined_without_a_denominator():
    score = score_findings([], (), FIXED)
    assert score.precision is None
    assert score.recall is None


def test_a_miss_is_recall_zero_not_undefined():
    assert score_findings([], TRUTH, VULNERABLE).recall == 0.0


def test_every_finding_on_fixed_code_is_a_false_accusation_even_if_the_case_declares_truth():
    # The archive fixed tree shares a case.json with the vulnerable tree and its ground truth.
    score = score_findings([Finding("path_traversal", "pkg/app.py")], TRUTH, FIXED)
    assert (score.true_positives, score.false_positives, score.false_accusations) == (0, 1, 1)
    assert score.recall is None


def test_an_incomplete_fix_keeps_its_ground_truth():
    score = score_findings([Finding("path_traversal", "pkg/app.py")], TRUTH, INCOMPLETE)
    assert (score.true_positives, score.false_accusations) == (1, 0)


def test_combine_recomputes_ratios_from_the_sums():
    parts = [
        Score(reported=2, true_positives=2, truth_total=2, truth_found=2, calls=1, cost_usd=0.5, live_usd=0.5),
        Score(reported=2, false_positives=2, false_accusations=2, calls=3, cost_usd=0.25, live_usd=1.0,
              model_wall_s=4.0, discarded=1),
    ]
    total = combine(parts)
    assert (total.reported, total.true_positives, total.false_accusations, total.calls) == (4, 2, 2, 4)
    assert total.precision == pytest.approx(0.5)
    assert total.recall == 1.0
    assert (total.cost_usd, total.live_usd, total.model_wall_s, total.discarded) == (0.75, 1.5, 4.0, 1)


# -- the naive reporter --------------------------------------------------------------------------


def test_naive_answers_are_schema_validated():
    jsonschema.validate({"findings": [{"class": "x", "file": "a.py", "line": 1, "description": "d"}]}, NAIVE_SCHEMA)
    with pytest.raises(SchemaValidationError):
        jsonschema.validate({"findings": [{"class": "x"}]}, NAIVE_SCHEMA)
    with pytest.raises(SchemaValidationError):
        jsonschema.validate({"issues": []}, NAIVE_SCHEMA)


def test_naive_prompt_is_plain_and_does_not_name_the_tree(tmp_path):
    for tree in ("vulnerable", "fixed", "fixed_incomplete"):
        target = Target(ARCHIVE, VULNERABLE, tree if tree != "vulnerable" else "")
        file, source = target_source(target, tmp_path)
        assert file == "archive.py"
        prompt = naive_prompt(source, file)
        assert prompt.startswith("List the vulnerabilities in this code.")
        assert source in prompt


def test_each_tree_gets_its_own_source(tmp_path):
    sources = {target_source(t, tmp_path)[1] for t in TARGETS if t.case_id == ARCHIVE}
    assert len(sources) == 3


def test_naive_recordings_are_real_capped_minimal_effort_meta_calls():
    spent = 0.0
    for target in TARGETS:
        recording, metadata = naive_paths(target)
        meta = json.loads(metadata.read_text(encoding="utf-8"))
        rows = [json.loads(line) for line in recording.read_text(encoding="utf-8").splitlines() if line]
        assert (meta["provider"], meta["model"], meta["reasoning_effort"]) == ("meta", DEFAULT_MODEL, "minimal")
        assert meta["hand_authored"] is False
        assert meta["error"] == ""
        assert len(rows) == meta["calls"] == 1
        assert rows[0]["model"] != "hand-authored"
        assert scan_files([recording, metadata], scan_values()) == []
        spent += rows[0]["cost_usd"]
    assert spent <= baseline.RECORD_BUDGET_USD


def test_replaying_naive_needs_no_key_and_no_network(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("a replay must not call the model API")

    monkeypatch.delenv("META_API_KEY", raising=False)
    monkeypatch.setattr("exhibit_a.models.openai_compat.post_json", no_network)
    target = Target(ARCHIVE, VULNERABLE)
    score = replay_naive(target, tmp_path)
    assert (score.reported, score.true_positives, score.recall) == (1, 1, 1.0)
    fixed = replay_naive(Target(ARCHIVE, FIXED, "fixed", paired=False), tmp_path)
    assert (fixed.reported, fixed.false_accusations) == (0, 0)


def test_a_missing_naive_recording_is_an_error_not_an_empty_score(tmp_path):
    with pytest.raises(FileNotFoundError):
        replay_naive(Target(ARCHIVE, FIXED, "no-such-tree", paired=False), tmp_path)


# -- fail closed: a broken replay never becomes a table ------------------------------------------


@pytest.mark.parametrize("outcome", [
    CaseOutcome(ARCHIVE, baseline_ok=False),  # e.g. Docker went away
    CaseOutcome(ARCHIVE, baseline_ok=True, aborted="adversary output rejected"),
    CaseOutcome(ARCHIVE, baseline_ok=True, stopped="replay_miss"),
])
def test_a_broken_exhibit_a_replay_raises(outcome, tmp_path, monkeypatch):
    monkeypatch.setattr(baseline, "run_case", lambda *args, **kwargs: outcome)
    with pytest.raises(ComparisonError):
        replay_exhibit_a(Target(ARCHIVE, VULNERABLE), "compact", tmp_path)


def test_a_failed_comparison_writes_nothing(tmp_path, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise ComparisonError("sandbox down")

    monkeypatch.setattr(baseline, "compare", boom)
    doc = tmp_path / "bench.md"
    doc.write_text(f"{BEGIN_MARKER}\nold\n{END_MARKER}\n", encoding="utf-8")
    before = doc.read_text(encoding="utf-8")
    assert bench_main.main(["--compare", "baseline", "--out", str(tmp_path / "res"), "--doc", str(doc)]) == 1
    assert doc.read_text(encoding="utf-8") == before
    assert not (tmp_path / "res").exists()
    assert "comparison not written" in capsys.readouterr().err


def test_the_regular_bench_command_still_requires_its_arguments(capsys):
    with pytest.raises(SystemExit):
        bench_main.main([])
    assert "--corpus" in capsys.readouterr().err


# -- the generated section -----------------------------------------------------------------------


def test_update_doc_replaces_only_the_generated_section(tmp_path):
    doc = tmp_path / "bench.md"
    doc.write_text(f"before\n{BEGIN_MARKER}\nold table\n{END_MARKER}\nafter\n", encoding="utf-8")
    update_doc(doc, "new table\n")
    assert doc.read_text(encoding="utf-8") == f"before\n{BEGIN_MARKER}\nnew table\n{END_MARKER}\nafter\n"


def test_update_doc_refuses_a_document_without_markers(tmp_path):
    doc = tmp_path / "bench.md"
    doc.write_text("no markers\n", encoding="utf-8")
    with pytest.raises(ComparisonError):
        update_doc(doc, "table\n")


def test_render_shows_na_and_marks_unmeasured_targets():
    result = Comparison(
        per_target=[baseline._row(COMPACT_LABEL, Target(ARCHIVE, FIXED, "fixed", paired=False), None)],
        systems={COMPACT_LABEL: Score()},
    )
    section = render_section(result)
    assert f"| {COMPACT_LABEL} | 0 | 0 | 0 | 0 | n/a | n/a |" in section
    assert f"{ARCHIVE}/fixed | fixed | - |" in section


# -- end to end, offline, through the sandbox and the current oracle -----------------------------


def _generated(text: str) -> str:
    return text.partition(BEGIN_MARKER)[2].partition(END_MARKER)[0]


@pytest.mark.docker
def test_comparison_runs_offline_is_reproducible_and_matches_the_committed_doc(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("the comparison must not call the model API")

    monkeypatch.delenv("META_API_KEY", raising=False)
    monkeypatch.setattr("exhibit_a.models.openai_compat.post_json", no_network)
    doc = tmp_path / "bench.md"
    results = []
    sections = []
    for attempt in ("one", "two"):
        doc.write_text(f"{BEGIN_MARKER}\n{END_MARKER}\n", encoding="utf-8")
        out = tmp_path / attempt
        assert bench_main.main(["--compare", "baseline", "--out", str(out), "--doc", str(doc)]) == 0
        files = list(out.iterdir())
        assert len(files) == 1 and re.fullmatch(r"\d{4}-\d{2}-\d{2}\.json", files[0].name)
        results.append(json.loads(files[0].read_text(encoding="utf-8")))
        sections.append(doc.read_text(encoding="utf-8"))
    assert sections[0] == sections[1]
    results[0].pop("volatile"), results[1].pop("volatile")
    assert results[0] == results[1]
    assert _generated(sections[0]) == _generated(DOC_PATH.read_text(encoding="utf-8"))

    systems = results[0]["systems"]
    naive, compact, standard = systems[NAIVE_LABEL], systems[COMPACT_LABEL], systems[STANDARD_LABEL]
    # The naive model finds both vulnerabilities too, and accuses the fixed Starlette tree.
    assert (naive["reported"], naive["true_positives"], naive["false_accusations"]) == (3, 2, 1)
    assert naive["recall"] == 1.0
    # Compact: both proven and nothing on fixed code, under today's oracle.
    assert (compact["reported"], compact["true_positives"], compact["false_positives"]) == (2, 2, 0)
    assert compact["recall"] == 1.0
    # Standard: Exhibit A misses both real vulnerabilities, and the table says so.
    assert (standard["reported"], standard["recall"], standard["discarded"]) == (0, 0.0, 17)
    # Costs are real model calls: the standard replay spends exactly what the live run did.
    assert standard["cost_usd"] == pytest.approx(4.7824, abs=1e-4)
    assert standard["calls"] == 20


@pytest.mark.docker
def test_the_false_proof_in_the_metadata_does_not_reach_the_score(tmp_path, monkeypatch):
    monkeypatch.delenv("META_API_KEY", raising=False)
    _, metadata = recording_paths(STARLETTE_FIXED, DEFAULT_MODEL, "compact")
    recorded = json.loads(metadata.read_text(encoding="utf-8"))["verdicts"]
    assert [v["suspicion_id"] for v in recorded if v["verdict"] == "proven"] == ["S3"]
    score = replay_exhibit_a(Target(STARLETTE_FIXED, FIXED), "compact", tmp_path)
    assert (score.reported, score.false_accusations, score.discarded) == (0, 0, 3)
    # The live run went on to the fixer and the defender for that false proof; the replay does not.
    assert score.cost_usd < score.live_usd

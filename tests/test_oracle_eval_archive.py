"""Oracle evaluation set across both vulnerability classes.

A labelled set of exploit-test variants is judged by the *real* oracle and scored. Positives
are genuine exploits that must be proven; every other label (benign, wrong-reason, cheating,
flaky) is a negative that must NOT be proven. Each case is run ``RUNS`` times and counts as
proven only if every run is a stable proof, so a flaky exploit is correctly a negative.

The confusion matrix and the real precision/recall are written to ``docs/oracle-eval.md``. The
thresholds below are a floor, not a tuning knob: the numbers reported are whatever the oracle
actually produces, and a false positive (proving a non-vulnerability) fails the test outright.

Covers:
* the existing path-traversal **read** class (``tests/fixtures/oracle_eval``);
* the new archive-extraction **write** class
  (``bench/corpus/archive-extraction-pathtraversal``);
* the audit A-11 F2 cheats (``tests/fixtures/oracle_eval/audit_f2``): tests that root a SAFE
  app at the canary's directory (P1, P1b) or gate that on the source hash (P7). They run
  against the safe app of their class, so any proof is a false proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from exhibit_a.oracle import run_oracle

RUNS = 3
ROOT = Path(__file__).resolve().parent.parent
READ_ROOT = Path(__file__).parent / "fixtures" / "oracle_eval"
WRITE_CASE = ROOT / "bench" / "corpus" / "archive-extraction-pathtraversal"
ENTRY_POINTS = {"App.handle_request"}
DOC = ROOT / "docs" / "oracle-eval.md"
AUDIT_F2 = READ_ROOT / "audit_f2"


@dataclass(frozen=True)
class EvalCase:
    name: str
    vuln_class: str
    app_root: Path
    exploit: Path
    effect: str
    label: str
    counter: Path | None = None  # a flaky case's run-counter file, cleared around the runs

    @property
    def is_positive(self) -> bool:
        return self.label == "true-exploit"


def _read(name, exploit, label, counter=None, *, app="vulnerable", exploits=READ_ROOT / "exploits"):
    return EvalCase(
        name=name, vuln_class="path_traversal_read", app_root=READ_ROOT / app,
        exploit=exploits / exploit, effect="canary_read", label=label,
        counter=(exploits / counter) if counter else None,
    )


def _write(name, exploit, label, counter=None, *, app="vulnerable", exploits=WRITE_CASE / "exploits"):
    return EvalCase(
        name=name, vuln_class="archive_extraction_write", app_root=WRITE_CASE / app,
        exploit=exploits / exploit, effect="canary_write", label=label,
        counter=(exploits / counter) if counter else None,
    )


CASES = [
    # Existing path-traversal (read) class.
    _read("read/true-traversal", "exploit_true_path_traversal.py", "true-exploit"),
    _read("read/benign-inside", "exploit_benign_inside_allowed.py", "benign"),
    _read("read/wrong-reason-crash", "exploit_wrong_reason_crash.py", "wrong-reason-failure"),
    _read("read/cheat-opens-canary", "exploit_cheat_opens_canary.py", "cheating"),
    _read("read/cheat-calls-sink", "exploit_cheat_calls_sink_directly.py", "cheating"),
    _read("read/mock-fabricated", "exploit_mock_fabricated_leak.py", "cheating"),
    _read("read/flaky", "exploit_flaky_path_traversal.py", "flaky", counter=".flaky_run_count"),
    # New archive-extraction (write) class.
    _write("write/true-relative", "exploit_true_relative.py", "true-exploit"),
    _write("write/true-absolute", "exploit_true_absolute.py", "true-exploit"),
    _write("write/benign-safe", "exploit_benign_safe_archive.py", "benign"),
    _write("write/wrong-reason-crash", "exploit_wrong_reason_crash.py", "wrong-reason-failure"),
    _write("write/cheat-writes-canary", "exploit_cheat_writes_canary.py", "cheating"),
    _write("write/cheat-calls-sink", "exploit_cheat_calls_sink_directly.py", "cheating"),
    _write("write/mock-fabricated", "exploit_mock_fabricated_escape.py", "cheating"),
    _write("write/flaky", "exploit_flaky_escape.py", "flaky", counter=".flaky_escape_count"),
    # Audit A-11 F2: the test chooses where a SAFE app is rooted (never a proof).
    _read("read/cheat-p1b-plain-base-is-canary-dir", "exploit_p1b_plain_base_is_canary_dir.py", "cheating",
          app="fixed", exploits=AUDIT_F2),
    _read("read/cheat-p1b-derived-base-is-canary-dir", "exploit_p1b_derived_base_is_canary_dir.py", "cheating",
          app="fixed", exploits=AUDIT_F2),
    _write("write/cheat-p1-plain-dest-is-canary-dir", "exploit_p1_plain_dest_is_canary_dir.py", "cheating",
           app="fixed", exploits=AUDIT_F2),
    _write("write/cheat-p1-derived-dest-is-canary-dir", "exploit_p1_derived_dest_is_canary_dir.py", "cheating",
           app="fixed", exploits=AUDIT_F2),
    _write("write/cheat-p7-plain-gated-on-source", "exploit_p7_plain_gated_on_source.py", "cheating",
           app="fixed", exploits=AUDIT_F2),
]


def _clear(counter: Path | None) -> None:
    if counter and counter.exists():
        counter.unlink()


def _is_proof(result) -> bool:
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


@dataclass
class Scored:
    case: EvalCase
    proven_runs: int
    predicted_proven: bool
    reason: str


def _score(case: EvalCase) -> Scored:
    _clear(case.counter)
    try:
        results = [
            run_oracle(case.app_root, case.exploit, ENTRY_POINTS, effect=case.effect)
            for _ in range(RUNS)
        ]
    finally:
        _clear(case.counter)
    proven_runs = sum(1 for r in results if _is_proof(r))
    # Stable proof only: proven on every run. A flaky exploit proven on some runs is not a proof.
    predicted = proven_runs == RUNS
    return Scored(case=case, proven_runs=proven_runs, predicted_proven=predicted, reason=results[0].reason)


def _confusion(scored: list[Scored]) -> dict[str, int]:
    matrix = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for s in scored:
        if s.case.is_positive and s.predicted_proven:
            matrix["tp"] += 1
        elif s.case.is_positive and not s.predicted_proven:
            matrix["fn"] += 1
        elif not s.case.is_positive and s.predicted_proven:
            matrix["fp"] += 1
        else:
            matrix["tn"] += 1
    return matrix


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else numerator / denominator


def _write_report(scored: list[Scored], m: dict[str, int], precision: float, recall: float) -> None:
    lines = [
        "# Oracle evaluation set",
        "",
        "Generated by `tests/test_oracle_eval_archive.py`. Each case is judged by the real oracle,",
        f"run {RUNS} times; a case counts as *proven* only if every run is a stable proof. Positives",
        "are genuine exploits (`true-exploit`); every other label must NOT be proven. These are real",
        "numbers, not tuned: a false positive fails the test.",
        "",
        "## Cases",
        "",
        "| case | class | label | actual | predicted | proven runs | oracle reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in sorted(scored, key=lambda s: s.case.name):
        actual = "positive" if s.case.is_positive else "negative"
        predicted = "PROVEN" if s.predicted_proven else "not proven"
        reason = s.reason.replace("|", "\\|")
        if len(reason) > 80:
            reason = reason[:77] + "..."
        lines.append(
            f"| {s.case.name} | {s.case.vuln_class} | {s.case.label} | {actual} | "
            f"{predicted} | {s.proven_runs}/{RUNS} | {reason} |"
        )
    total_pos = m["tp"] + m["fn"]
    total_neg = m["tn"] + m["fp"]
    lines += [
        "",
        "## Confusion matrix",
        "",
        "| | predicted proven | predicted not proven |",
        "|---|---|---|",
        f"| **actual positive** ({total_pos}) | TP = {m['tp']} | FN = {m['fn']} |",
        f"| **actual negative** ({total_neg}) | FP = {m['fp']} | TN = {m['tn']} |",
        "",
        "## Metrics",
        "",
        f"- precision = TP / (TP + FP) = {m['tp']} / {m['tp'] + m['fp']} = **{precision:.3f}**",
        f"- recall = TP / (TP + FN) = {m['tp']} / {m['tp'] + m['fn']} = **{recall:.3f}**",
        f"- cases: {len(scored)} ({total_pos} positive, {total_neg} negative)",
        "",
        "A false positive would mean the oracle proved a non-vulnerability (a benign, cheating or",
        "flaky test accepted as a proof); `FP = 0` is the property the engine's thesis depends on.",
        "The sandbox that runs untrusted tests is isolated and resource-limited, never \"100% safe\".",
        "",
    ]
    try:
        DOC.write_text("\n".join(lines), encoding="utf-8")
    except OSError:
        pass  # best-effort: the assertions below are the real test


def test_oracle_eval_precision_recall():
    scored = [_score(case) for case in CASES]
    m = _confusion(scored)
    precision = _ratio(m["tp"], m["tp"] + m["fp"])
    recall = _ratio(m["tp"], m["tp"] + m["fn"])
    _write_report(scored, m, precision, recall)

    assert len(CASES) >= 12, "the eval set must hold at least 12 labelled variants"
    # The engine's core promise: never prove a non-vulnerability.
    false_positives = [s.case.name for s in scored if not s.case.is_positive and s.predicted_proven]
    assert not false_positives, f"false positives (proved a non-vulnerability): {false_positives}"
    missed = [s.case.name for s in scored if s.case.is_positive and not s.predicted_proven]
    assert precision >= 0.95, f"precision {precision:.3f} below floor; FP={m['fp']}"
    assert recall >= 0.95, f"recall {recall:.3f} below floor; missed positives: {missed}"


def test_both_classes_are_represented():
    classes = {c.vuln_class for c in CASES}
    assert classes == {"path_traversal_read", "archive_extraction_write"}
    for vuln_class in classes:
        labels = {c.label for c in CASES if c.vuln_class == vuln_class}
        assert "true-exploit" in labels
        assert labels & {"benign", "wrong-reason-failure", "cheating", "flaky"}

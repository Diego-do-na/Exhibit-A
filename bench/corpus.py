"""Corpus loading: a list of cases, each a vulnerable commit, a fixed commit or a clean diff."""

import json
from dataclasses import dataclass, field
from pathlib import Path

KINDS = ("vulnerable", "fixed", "clean")


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    repo: str
    commit: str
    # Known vulnerabilities as {"class": ..., "file": ...}. Empty for fixed/clean cases.
    ground_truth: tuple[dict[str, str], ...] = ()
    # Scripted behaviour for the synthetic pipeline; real corpora leave this empty.
    synthetic: dict = field(default_factory=dict)


def load_corpus(path: str | Path) -> list[Case]:
    """Read a corpus JSON file: ``{"cases": [{id, kind, repo, commit, ground_truth}]}``."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases: list[Case] = []
    seen: set[str] = set()
    for raw in data["cases"]:
        case = Case(
            id=raw["id"],
            kind=raw["kind"],
            repo=raw.get("repo", ""),
            commit=raw.get("commit", ""),
            ground_truth=tuple(raw.get("ground_truth", [])),
            synthetic=raw.get("synthetic", {}),
        )
        if case.kind not in KINDS:
            raise ValueError(f"case {case.id}: kind must be one of {KINDS}")
        if case.kind != "vulnerable" and case.ground_truth:
            raise ValueError(f"case {case.id}: only vulnerable cases have ground truth")
        if case.id in seen:
            raise ValueError(f"duplicate case id {case.id}")
        seen.add(case.id)
        cases.append(case)
    return cases

"""Corpus loading: a list of cases, each a vulnerable commit, a fixed commit or a clean diff.

Two layouts are accepted:

* a legacy synthetic JSON file ``{"cases": [...]}`` (see ``bench/synthetic.py``);
* a real case directory holding ``case.json`` with a ``run`` section that says how
  to execute it (source tree, baseline test, recording, requirements, effect);
* a corpus-root directory holding one case directory per case.

Real cases never resolve their source from ``repo`` when it is a URL: the tree
comes from the case directory (``run.tree`` or ``run.trees``) or from installing
``run.requirements``. ``repo`` stays informational.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

KINDS = ("vulnerable", "fixed", "clean")

#: Observed effects the oracle can prove. ``canary_read`` is the original
#: path-traversal style effect; ``canary_write`` is the archive-extraction /
#: zip-slip style effect (the app creates a file outside the allowed directory);
#: ``canary_exec`` is command execution; ``canary_sql`` is SQL injection (the app reads a row
#: of a table it never queries, in the SQLite database ``run.sql_db`` declares);
#: ``canary_redirect`` is open redirect (the app's response redirects to a per-run canary
#: host); ``canary_access`` is broken access control (the app returns a victim-owned
#: resource to an attacker-authenticated request, seeded into ``run.access_db`` for the
#: principals ``run.access`` declares).
EFFECTS = (
    "canary_read", "canary_write", "canary_exec", "canary_sql", "canary_connect", "canary_dos",
    "canary_redirect", "canary_access",
)


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
    # Directory holding this case's case.json ("" for legacy file-only corpora).
    case_dir: str = ""
    # Source-tree selector from the run section ("" when the case installs it).
    tree: str = ""
    # Baseline test file name inside the case directory.
    baseline_test: str = "test_baseline.py"
    # Replay recording file name inside the case directory ("" when replay-driven
    # runs are not available for this case).
    recording: str = ""
    # Pip requirements installed to stage the case's source tree.
    requirements: tuple[str, ...] = ()
    # Which oracle effect proves this case (see EFFECTS).
    effect: str = "canary_read"
    # Source file the loop inspects, relative to the staged source tree.
    source_file: str = ""
    # canary_sql only: the application's SQLite database, a path inside the source tree that the
    # sandbox copies, seeds with the canary table and mounts read-only at that path ("" otherwise).
    sql_db: str = ""
    # canary_access only: the application's JSON store, a path inside the source tree that the
    # sandbox copies, seeds with the victim-owned resource and mounts read-only at that path.
    access_db: str = ""
    # canary_access only: the principals and the protected resource (case.json run.access:
    # attacker and victim credentials, resource id). The test learns only the attacker
    # credential and the resource.
    access: dict = field(default_factory=dict)
    # canary_redirect only: whether an HTML meta refresh to the canary host counts next to
    # a 3xx Location (case.json run.redirect_meta).
    redirect_meta: bool = False
    # True for a case nobody tuned on: written after the compact profile and the oracle were
    # frozen, from a public advisory (case.json ``held_out``). Docs and tables use it to keep
    # held-out results apart from the tuned ones.
    held_out: bool = False


def _check_common(raw: dict, seen: set[str]) -> None:
    if raw.get("kind") not in KINDS:
        raise ValueError(f"case {raw.get('id')}: kind must be one of {KINDS}")
    if raw.get("kind") != "vulnerable" and raw.get("ground_truth"):
        raise ValueError(f"case {raw.get('id')}: only vulnerable cases have ground truth")
    if raw.get("id") in seen:
        raise ValueError(f"duplicate case id {raw.get('id')}")
    seen.add(raw["id"])


def _case_from_legacy(raw: dict) -> Case:
    return Case(
        id=raw["id"],
        kind=raw["kind"],
        repo=raw.get("repo", ""),
        commit=raw.get("commit", ""),
        ground_truth=tuple(raw.get("ground_truth", [])),
        synthetic=raw.get("synthetic", {}),
    )


def _held_out(raw: dict, top: dict) -> bool:
    """The ``held_out`` flag of a case: on its entry, else at the top of case.json; default False."""
    value = raw.get("held_out", top.get("held_out", False))
    if not isinstance(value, bool):
        raise ValueError(f"case {raw.get('id')}: held_out must be true or false, not {value!r}")
    return value


def _case_from_real(case_dir: Path, raw: dict, run: dict, top: dict | None = None) -> Case:
    """Build a Case from one entry of a real case.json ``cases`` list."""
    effect = run.get("effect") or _profile_effect(case_dir) or "canary_read"
    if effect not in EFFECTS:
        raise ValueError(f"case {raw.get('id')}: unknown run.effect {effect!r}")
    sql_db = run.get("sql_db", "")
    if effect == "canary_sql" or sql_db:
        from exhibit_a.oracle.oracle import sql_db_shape_problem

        if effect != "canary_sql":
            raise ValueError(f"case {raw.get('id')}: run.sql_db is only for the canary_sql effect")
        problem = sql_db_shape_problem(sql_db)
        if problem is not None:
            raise ValueError(f"case {raw.get('id')}: run.sql_db: {problem}")
    access_db = run.get("access_db", "")
    access = run.get("access") or {}
    if effect == "canary_access" or access_db or access:
        from exhibit_a.oracle.oracle import access_db_shape_problem, access_shape_problem

        if effect != "canary_access":
            raise ValueError(f"case {raw.get('id')}: run.access_db and run.access are only for the canary_access effect")
        problem = access_db_shape_problem(access_db)
        if problem is not None:
            raise ValueError(f"case {raw.get('id')}: run.access_db: {problem}")
        problem = access_shape_problem(access)
        if problem is not None:
            raise ValueError(f"case {raw.get('id')}: run.access: {problem}")
    redirect_meta = run.get("redirect_meta", False)
    if effect == "canary_redirect" or redirect_meta:
        if effect != "canary_redirect":
            raise ValueError(f"case {raw.get('id')}: run.redirect_meta is only for the canary_redirect effect")
        if not isinstance(redirect_meta, bool):
            raise ValueError(f"case {raw.get('id')}: run.redirect_meta must be true or false")
    trees = run.get("trees") or {}
    tree = run.get("tree") or trees.get("vulnerable", "")
    requirements = tuple(str(item) for item in run.get("requirements", []))
    return Case(
        id=raw["id"],
        kind=raw["kind"],
        repo=raw.get("repo", ""),
        commit=raw.get("commit", ""),
        ground_truth=tuple(raw.get("ground_truth", [])),
        synthetic=raw.get("synthetic", {}),
        case_dir=str(case_dir),
        tree=str(tree),
        baseline_test=str(run.get("baseline_test", "test_baseline.py")),
        recording=str(run.get("recording", "")),
        requirements=requirements,
        effect=effect,
        source_file=str(run.get("source_file", "")),
        sql_db=sql_db,
        access_db=access_db,
        access=dict(access),
        redirect_meta=bool(redirect_meta),
        held_out=_held_out(raw, top or {}),
    )


def _profile_effect(case_dir: Path) -> str:
    """Read the effect from profile.json when the case declares one there."""
    profile = case_dir / "profile.json"
    if not profile.is_file():
        return ""
    try:
        data = json.loads(profile.read_text(encoding="utf-8"))
    except ValueError:
        return ""
    effect = data.get("effect", "")
    return effect if isinstance(effect, str) else ""


def _load_case_file(case_file: Path) -> list[Case]:
    """Load one case.json file (real or legacy); may hold several cases."""
    data = json.loads(case_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "cases" not in data:
        raise ValueError(f"{case_file}: expected a mapping with a 'cases' list")
    run = data.get("run") or {}
    cases: list[Case] = []
    seen: set[str] = set()
    for raw in data["cases"]:
        _check_common(raw, seen)
        if run:
            cases.append(_case_from_real(case_file.parent, raw, run, data))
        else:
            cases.append(_case_from_legacy(raw))
    return cases


def load_corpus(path: str | Path) -> list[Case]:
    """Read cases from a JSON file, a single case directory, or a corpus root.

    * file: a legacy ``{"cases": [...]}`` corpus or a single real ``case.json``;
    * directory holding ``case.json``: that one case;
    * directory of case directories: every immediate child holding ``case.json``,
      sorted by directory name.
    """
    root = Path(path)
    if root.is_dir():
        direct = root / "case.json"
        if direct.is_file():
            return _load_case_file(direct)
        cases: list[Case] = []
        seen: set[str] = set()
        for child in sorted(p for p in root.iterdir() if p.is_dir()):
            case_file = child / "case.json"
            if not case_file.is_file():
                continue
            for case in _load_case_file(case_file):
                if case.id in seen:
                    raise ValueError(f"duplicate case id {case.id}")
                seen.add(case.id)
                cases.append(case)
        if not cases:
            raise ValueError(f"{root}: no case.json found in any immediate subdirectory")
        return cases
    if not root.is_file():
        raise FileNotFoundError(f"corpus not found: {root}")
    return _load_case_file(root)

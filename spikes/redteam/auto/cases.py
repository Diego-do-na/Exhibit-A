"""Corpus targets for the automated red team.

A target is one corpus case's FIXED tree: the generated cheating test must make
the oracle declare ``proven`` there, so any proof is false by construction.
Targets are discovered from ``bench/corpus/*/case.json`` (cases with a
``run.trees.fixed`` entry). Cases without a fixed tree (the Starlette CVE
pair, which predates the trees layout) are skipped with a note.

``--lang js`` hook (for T125, the Node oracle task): this module keeps a
``JS_TARGETS`` registry, empty until the Node task fills it. ``discover`` with
``lang="js"`` returns those registrations instead of the Python corpus, and the
engine accepts any ``run_fn`` so the Node task can plug its own
sandbox-backed runner without touching this package. See ``register_js_target``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json


@dataclass(frozen=True)
class Target:
    """One fixed tree to attack."""

    case_id: str
    effect: str
    fixed_dir: Path
    entry_points: frozenset[str] = frozenset({"App.handle_request"})
    sql_db: str | None = None
    access_db: str | None = None
    access: dict[str, str] | None = None
    redirect_meta: bool = False
    requirements: tuple[str, ...] = ()
    lang: str = "py"


#: Node-oracle targets, registered by the T125 task. Empty until then: each
#: entry is a ``Target`` with ``lang="js"`` plus a runner the Node task owns.
#: The engine never interprets these; it only passes them to ``run_fn``.
JS_TARGETS: list[Target] = []


def register_js_target(target: Target) -> None:
    """Register one Node-oracle target (hook for the T125 task).

    The Node task owns the target contents and the ``run_fn`` that executes a
    generated JS test against them; this registry is only the handoff point so
    ``python -m spikes.redteam.auto --lang js`` has something to iterate over.
    """
    if target.lang != "js":
        raise ValueError("JS targets must use lang='js'")
    JS_TARGETS.append(target)


def _case_targets(case_dir: Path) -> list[Target]:
    case_file = case_dir / "case.json"
    try:
        case = json.loads(case_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    run = case.get("run", {})
    effect = run.get("effect", "canary_read")
    trees = run.get("trees") or {}
    fixed = trees.get("fixed")
    if fixed is None:
        return []  # No fixed tree: nothing to cheat against (e.g. Starlette pair).
    entry_points = run.get("entry_points") or ([run["oracle_entry_point"]] if run.get("oracle_entry_point") else [])
    if not entry_points:
        return []
    access = run.get("access")
    return [Target(
        case_id=case_dir.name,
        effect=effect,
        fixed_dir=(case_dir / fixed).resolve(),
        entry_points=frozenset(entry_points),
        sql_db=run.get("sql_db"),
        access_db=run.get("access_db"),
        access=dict(access) if isinstance(access, dict) else None,
        redirect_meta=bool(run.get("redirect_meta", False)),
        requirements=tuple(run.get("requirements", ())),
        lang="py",
    )]


def discover(
    effect: str,
    corpus_root: Path,
    *,
    lang: str = "py",
) -> tuple[list[Target], list[str]]:
    """Find fixed-tree targets for ``effect`` (or ``"all"``).

    Returns ``(targets, skipped)`` where ``skipped`` names corpus cases with no
    usable fixed tree. With ``lang="js"`` the Python corpus is ignored and the
    ``JS_TARGETS`` registry (hook for T125) is returned instead.
    """
    if lang == "js":
        wanted = [t for t in JS_TARGETS if effect in ("all", t.effect)]
        return wanted, []
    targets: list[Target] = []
    skipped: list[str] = []
    for case_dir in sorted(corpus_root.iterdir()):
        if not case_dir.is_dir() or not (case_dir / "case.json").exists():
            continue
        found = _case_targets(case_dir)
        if not found:
            skipped.append(case_dir.name)
            continue
        for target in found:
            if effect in ("all", target.effect):
                if not target.fixed_dir.is_dir():
                    skipped.append(f"{target.case_id} (missing {target.fixed_dir})")
                    continue
                targets.append(target)
    return targets, skipped

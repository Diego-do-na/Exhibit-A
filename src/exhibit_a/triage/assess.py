"""PR triage: how risky is it to execute anything for this change?

Input is only the changed-file list and the unified diff text. Nothing is
executed, imported, installed or applied, and the diff is never interpolated
into a shell or ``eval``. Output is a deterministic ``Triage``: a level
(low/medium/high, the same ``Risk`` enum as ``exhibit_a.ci.gate``), sorted
reasons, and a decision:

- low    -> ``run``
- medium -> ``needs_approval``
- high   -> ``refuse``

Rules (the highest level over all paths wins; every path spelling of a
rename/copy is classified):

- high: CI workflows/actions, ``action.yml``, ``setup.py``/``setup.cfg``,
  ``pyproject.toml`` edits that touch a build backend, build requirements or
  hooks (or whose section cannot be seen: fail closed), ``conftest.py``,
  ``*.pth``, ``sitecustomize.py``/``usercustomize.py``, container files, install
  scripts, binary files, symlinks, unsafe paths (absolute, ``..``, NUL or
  control characters, over-long), and inputs over the size/file-count caps or
  where the diff touches files missing from the changed-file list.
- medium: dependency files, test infrastructure (fixtures, helpers, tox/nox/
  pytest configuration), newly executable files.
- low: documentation and plain source, tests included.

Rule data reuse: the CI-workflow, container, dependency and documentation
tables are imported from ``exhibit_a.ci.gate`` (looked up by their reason
text, which ``tests/test_triage.py`` pins), so both modules agree on them.

Delegation plan for ``ci/gate.py`` (not done here: ``ci/`` is out of scope):
``gate.classify(paths)`` should become a thin adapter that calls
``triage.assess(paths, diff)`` and maps ``Triage.level`` to ``Risk`` (same
enum) and ``should_run_exploits(risk)`` to ``decision is Decision.RUN``. The
gate's ``Classification.reasons`` can be filled from ``Triage.reasons``.
``action.yml`` then needs to pass ``git diff BASE...HEAD`` to the gate as a
file; without a diff, ``assess(paths, None)`` still works but fails closed on
``pyproject.toml`` because its content cannot be inspected.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from exhibit_a.ci import gate
from exhibit_a.ci.gate import Risk
from exhibit_a.triage.diffparse import (
    MAX_DIFF_CHARS,
    MAX_FILES,
    MAX_PATH_CHARS,
    FileChange,
    parse_diff,
)

__all__ = ["Decision", "Triage", "assess", "Risk"]

MAX_REASONS = 50
_ORDER = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2}


class Decision(str, Enum):
    RUN = "run"
    NEEDS_APPROVAL = "needs_approval"
    REFUSE = "refuse"


_DECISION = {Risk.LOW: Decision.RUN, Risk.MEDIUM: Decision.NEEDS_APPROVAL, Risk.HIGH: Decision.REFUSE}


@dataclass(frozen=True)
class Triage:
    level: Risk
    decision: Decision
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"level": self.level.value, "decision": self.decision.value, "reasons": list(self.reasons)}


def _gate_rule(reason: str) -> gate.Rule:
    for rule in gate.RULES:
        if rule.reason == reason:
            return rule
    raise LookupError(f"ci.gate has no rule named {reason!r}")


_CI = _gate_rule("CI workflow or action definition")
_CONTAINER = _gate_rule("container definition")
_DEPENDENCY = _gate_rule("dependency manifest or lock file")
_DOCS = _gate_rule("documentation")

_BUILD_FILES = ("setup.py", "setup.cfg")
_PYPROJECT = "pyproject.toml"
# Dependency files that are reviewed by their content or are build files above.
_DEPENDENCY_NAMES = tuple(n for n in _DEPENDENCY.names if n not in (*_BUILD_FILES, _PYPROJECT))
_AUTORUN_NAMES = ("conftest.py", "sitecustomize.py", "usercustomize.py")
_AUTORUN_PATTERNS = ("*.pth",)
_INSTALL_SCRIPTS = (
    "install.sh", "install.bash", "install.bat", "install.cmd", "install.ps1", "install-*.sh",
    "install_*.sh", "*install.sh", "preinstall*", "postinstall*", "bootstrap.sh", "setup.sh",
    "configure", "makefile",
)
_BINARY_SUFFIXES = frozenset({
    ".so", ".dll", ".dylib", ".exe", ".bin", ".pyc", ".pyo", ".pyd", ".whl", ".egg", ".jar",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".class", ".o", ".a", ".wasm", ".node",
})
_TEST_INFRA_NAMES = ("tox.ini", "pytest.ini", "noxfile.py", ".coveragerc", "mypy.ini", ".flake8")
_TEST_INFRA_DIRS = ("fixtures", "helpers", "support", "utils", "plugins", "mocks")
_TEST_ROOTS = ("tests", "test")
_PYPROJECT_SENSITIVE = re.compile(
    r"build-system|build-backend|backend-path|cmdclass|\bhooks?\b"
    r"|\[tool\.(?:hatch\.build|setuptools|pdm\.build|poetry\.build|maturin|flit)"
    r"|^[ +-]\s*requires\s*=",
    re.IGNORECASE | re.MULTILINE,
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _safe(text: str) -> str:
    """Printable, bounded rendering of an untrusted string for reasons."""
    return _CONTROL.sub("?", text)[:120]


def _unsafe_path(path: str) -> str | None:
    if len(path) > MAX_PATH_CHARS:
        return "path too long"
    if _CONTROL.search(path):
        return "control character in path"
    text = path.replace("\\", "/")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        return "absolute path"
    if ".." in text.split("/"):
        return "path traversal"
    return None


def _matches(rule: gate.Rule, path: PurePosixPath) -> bool:
    return rule.matches(path)


def _classify(path: str, change: FileChange | None) -> tuple[Risk, str]:
    problem = _unsafe_path(path)
    if problem:
        return Risk.HIGH, problem
    clean = path.replace("\\", "/")
    while clean.startswith("./"):
        clean = clean[2:]
    posix = PurePosixPath(clean)
    name = posix.name.lower()
    suffix = posix.suffix.lower()
    parts = [p.lower() for p in posix.parts]

    if _matches(_CI, posix) or ".github" in parts[:-1]:
        return Risk.HIGH, "CI workflow or action definition"
    if name in _BUILD_FILES:
        return Risk.HIGH, "build script or configuration"
    if name == _PYPROJECT:
        if change is None or change.status != "modified" or not change.body:
            return Risk.HIGH, "pyproject.toml changed without an inspectable edit"
        if _PYPROJECT_SENSITIVE.search("\n".join(change.body)):
            return Risk.HIGH, "pyproject.toml build backend, build requirements or hooks"
        return Risk.MEDIUM, "dependency or project metadata"
    if name in _AUTORUN_NAMES or any(fnmatchcase(name, p) for p in _AUTORUN_PATTERNS):
        return Risk.HIGH, "file executed automatically by Python or pytest"
    if _matches(_CONTAINER, posix):
        return Risk.HIGH, "container definition"
    if any(fnmatchcase(name, p) for p in _INSTALL_SCRIPTS):
        return Risk.HIGH, "install or bootstrap script"
    if suffix in _BINARY_SUFFIXES:
        return Risk.HIGH, "binary file"
    if change is not None:
        if change.binary:
            return Risk.HIGH, "binary change"
        if "120000" in (change.old_mode, change.new_mode):
            return Risk.HIGH, "symbolic link"
    if any(fnmatchcase(name, p) for p in _DEPENDENCY_NAMES):
        return Risk.MEDIUM, "dependency manifest or lock file"
    if change is not None and change.new_mode == "100755":
        return Risk.MEDIUM, "executable file"
    in_tests = bool(parts[:-1]) and parts[0] in _TEST_ROOTS
    if name in _TEST_INFRA_NAMES or (
        in_tests and (name == "__init__.py" or any(d in _TEST_INFRA_DIRS for d in parts[1:-1]))
    ):
        return Risk.MEDIUM, "test infrastructure"
    if _matches(_DOCS, posix) and not in_tests:
        return Risk.LOW, "documentation"
    return Risk.LOW, "plain source"


def assess(changed_files: Iterable[str] | None, diff: str | bytes | None = None) -> Triage:
    """Triage a change from its file list and unified diff (either may be absent)."""
    findings: list[tuple[Risk, str]] = []
    listed: list[str] = []
    if changed_files is not None:
        for raw in changed_files:
            text = raw.strip("\n") if isinstance(raw, str) else ""
            if text.strip():
                listed.append(text)

    if isinstance(diff, bytes):
        oversize = len(diff) > MAX_DIFF_CHARS
        text = diff[:MAX_DIFF_CHARS].decode("utf-8", "replace")
    else:
        text = diff or ""
        oversize = len(text) > MAX_DIFF_CHARS
        text = text[:MAX_DIFF_CHARS]
    parsed = parse_diff(text)

    if oversize:
        findings.append((Risk.HIGH, f"diff exceeds {MAX_DIFF_CHARS} characters"))
    if parsed.truncated or len(listed) > MAX_FILES:
        findings.append((Risk.HIGH, f"more than {MAX_FILES} changed files"))
    if parsed.has_nul:
        findings.append((Risk.HIGH, "NUL byte in diff (binary content)"))

    changes: dict[str, FileChange] = {}
    for change in parsed.files:
        for path in change.paths:
            changes.setdefault(path, change)
    if changed_files is not None and parsed.files:
        known = set(listed)
        for change in parsed.files:
            if change.paths and not any(p in known for p in change.paths):
                findings.append((Risk.HIGH, f"diff touches {_safe(change.paths[-1])!r}, missing from changed-file list"))

    paths = list(dict.fromkeys([*listed, *changes]))
    for path in paths:
        level, why = _classify(path, changes.get(path))
        findings.append((level, f"{_safe(path)}: {why}"))

    level = max((lvl for lvl, _ in findings), key=_ORDER.__getitem__, default=Risk.LOW)
    ranked = sorted(set(findings), key=lambda f: (-_ORDER[f[0]], f[1]))
    reasons = [f"{lvl.value}: {why}" for lvl, why in ranked]
    if len(reasons) > MAX_REASONS:
        extra = len(reasons) - MAX_REASONS
        reasons = [*reasons[:MAX_REASONS], f"... {extra} more"]
    if not reasons:
        reasons = ["low: nothing to analyse"]
    return Triage(level, _DECISION[level], tuple(reasons))

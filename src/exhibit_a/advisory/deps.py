"""Parse a project's pinned dependencies from requirements files and pyproject.toml.

Only exact pins can be checked against an advisory, so only exact pins become
`PinnedDependency` values. Everything else is returned as an `Unsupported` entry with the
reason, never silently dropped: a range (``>=1.0``), a wildcard pin (``==1.*``), a URL or
VCS requirement, an editable install, an include (``-r other.txt``) or a constraint file.

Environment markers are kept as text and not evaluated: a pin behind ``; python_version <
"3.8"`` is still reported, with its marker, so a human can decide whether it applies.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass

from .version import InvalidVersion, Version

_NAME = re.compile(r"^\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*"
                   r"(?:\[(?P<extras>[^\]]*)\])?\s*(?P<rest>.*)$", re.DOTALL)
_PIN = re.compile(r"^(?P<op>===|==)\s*(?P<version>[^\s,;]+)\s*$")


def normalize_name(name: str) -> str:
    """PEP 503 normalized project name (``Foo_Bar.baz`` -> ``foo-bar-baz``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class PinnedDependency:
    name: str  # PEP 503 normalized
    version: str  # as written in the file
    source: str  # e.g. "requirements.txt:3" or "pyproject.toml:project.dependencies"
    marker: str | None = None
    extras: tuple[str, ...] = ()


@dataclass(frozen=True)
class Unsupported:
    text: str
    source: str
    reason: str


@dataclass
class ParseResult:
    dependencies: list[PinnedDependency]
    unsupported: list[Unsupported]


def parse_requirement(text: str, source: str) -> PinnedDependency | Unsupported:
    """Parse one PEP 508-style requirement string; accept only an exact pin."""
    raw = text.strip()
    if "@" in raw.split(";", 1)[0]:
        return Unsupported(raw, source, "direct URL reference; no version to compare")
    m = _NAME.match(raw)
    if m is None:
        return Unsupported(raw, source, "not a recognizable requirement")
    rest = m["rest"]
    marker = None
    if ";" in rest:
        rest, marker = rest.split(";", 1)
        marker = marker.strip() or None
    spec = rest.strip()
    if spec.startswith("(") and spec.endswith(")"):
        spec = spec[1:-1].strip()
    if not spec:
        return Unsupported(raw, source, "unpinned (no version specifier)")
    pin = _PIN.match(spec)
    if pin is None:
        return Unsupported(raw, source, f"not an exact pin ({spec!r}); ranges are not resolved")
    version = pin["version"]
    if "*" in version:
        return Unsupported(raw, source, f"wildcard pin ({spec!r}); ranges are not resolved")
    try:
        Version.parse(version)
    except InvalidVersion:
        if pin["op"] != "===":
            return Unsupported(raw, source, f"invalid PEP 440 version {version!r}")
        # '===' is arbitrary string equality; keep it, comparison may fail later.
    extras = tuple(e.strip() for e in (m["extras"] or "").split(",") if e.strip())
    return PinnedDependency(normalize_name(m["name"]), version, source, marker, extras)


def _logical_lines(text: str):
    """Yield (line_number, text) with backslash continuations joined and comments removed."""
    buf, start = "", 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not buf:
            start = number
        # A comment starts at '#' at line start or preceded by whitespace (pip's rule).
        line = re.sub(r"(^|\s)#.*$", "", line)
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            yield start, buf.strip()
        buf = ""
    if buf.strip():
        yield start, buf.strip()


def parse_requirements(text: str, filename: str = "requirements.txt") -> ParseResult:
    """Parse a pip requirements file. Includes (-r/-c) are reported, not followed."""
    deps: list[PinnedDependency] = []
    unsupported: list[Unsupported] = []
    for number, line in _logical_lines(text):
        source = f"{filename}:{number}"
        # Hash options belong to the requirement and do not change its version.
        line = re.sub(r"\s--hash[=\s]\S+", "", " " + line).strip()
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            unsupported.append(Unsupported(line, source, "include/constraint file not followed"))
            continue
        if line.startswith(("-e", "--editable")):
            unsupported.append(Unsupported(line, source, "editable install; no pinned version"))
            continue
        if line.startswith("-"):
            unsupported.append(Unsupported(line, source, "pip option, not a requirement"))
            continue
        if re.match(r"^(git\+|hg\+|svn\+|bzr\+|https?://|file:|\.{0,2}/)", line):
            unsupported.append(Unsupported(line, source, "URL, VCS or local path requirement"))
            continue
        result = parse_requirement(line, source)
        (deps if isinstance(result, PinnedDependency) else unsupported).append(result)
    return ParseResult(deps, unsupported)


def parse_pyproject(text: str, filename: str = "pyproject.toml") -> ParseResult:
    """Best-effort pinned dependencies from pyproject.toml.

    Read: ``[project].dependencies``, ``[project].optional-dependencies``,
    ``[dependency-groups]`` (string entries; ``include-group`` tables are reported as
    unsupported), and ``[tool.poetry.dependencies]`` / poetry groups where the constraint
    is an exact version. Poetry caret/tilde constraints, path/git tables and lock files
    are not resolved and are reported as unsupported.
    """
    data = tomllib.loads(text)
    deps: list[PinnedDependency] = []
    unsupported: list[Unsupported] = []

    def add_pep508(items, where: str) -> None:
        if not isinstance(items, list):
            unsupported.append(Unsupported(repr(items), f"{filename}:{where}", "not a list"))
            return
        for item in items:
            source = f"{filename}:{where}"
            if not isinstance(item, str):
                unsupported.append(Unsupported(repr(item), source, "non-string entry"))
                continue
            result = parse_requirement(item, source)
            (deps if isinstance(result, PinnedDependency) else unsupported).append(result)

    project = data.get("project", {})
    if isinstance(project, dict):
        if "dependencies" in project:
            add_pep508(project["dependencies"], "project.dependencies")
        if isinstance(project.get("dynamic"), list) and "dependencies" in project["dynamic"]:
            unsupported.append(Unsupported("dynamic = ['dependencies']",
                                           f"{filename}:project.dynamic",
                                           "dynamic dependencies are not resolved"))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, items in optional.items():
                add_pep508(items, f"project.optional-dependencies.{group}")

    groups = data.get("dependency-groups", {})
    if isinstance(groups, dict):
        for group, items in groups.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        unsupported.append(Unsupported(repr(item),
                                                       f"{filename}:dependency-groups.{group}",
                                                       "include-group not followed"))
                add_pep508([i for i in items if not isinstance(i, dict)],
                           f"dependency-groups.{group}")

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        tables = [("tool.poetry.dependencies", poetry.get("dependencies", {}))]
        for group, body in (poetry.get("group", {}) or {}).items():
            if isinstance(body, dict):
                tables.append((f"tool.poetry.group.{group}.dependencies",
                               body.get("dependencies", {})))
        for where, table in tables:
            if not isinstance(table, dict):
                continue
            for name, constraint in table.items():
                if normalize_name(name) == "python":
                    continue
                _add_poetry(name, constraint, f"{filename}:{where}", deps, unsupported)

    return ParseResult(deps, unsupported)


def _add_poetry(name, constraint, source, deps, unsupported) -> None:
    if isinstance(constraint, dict):
        if "version" not in constraint:
            unsupported.append(Unsupported(f"{name} = {constraint!r}", source,
                                           "path/git/url dependency; no version"))
            return
        constraint = constraint["version"]
    if not isinstance(constraint, str):
        unsupported.append(Unsupported(f"{name} = {constraint!r}", source, "unrecognized"))
        return
    spec = constraint.strip()
    if spec.startswith("=="):
        spec = spec[2:].strip()
    elif spec.startswith("="):
        spec = spec[1:].strip()
    # A bare poetry version is an exact pin; anything with an operator is a range.
    if not spec or re.search(r"[\^~<>!*,|\s]", spec):
        unsupported.append(Unsupported(f"{name} = {constraint!r}", source,
                                       "poetry range constraint; ranges are not resolved"))
        return
    try:
        Version.parse(spec)
    except InvalidVersion:
        unsupported.append(Unsupported(f"{name} = {constraint!r}", source,
                                       f"invalid PEP 440 version {spec!r}"))
        return
    deps.append(PinnedDependency(normalize_name(name), spec, source))

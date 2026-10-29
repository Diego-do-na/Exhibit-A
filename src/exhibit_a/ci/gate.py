"""Rule-based PR risk gate: decide from changed paths whether to run exploits.

This is a deliberately small placeholder. It classifies a pull request as
low, medium or high risk from the paths ``git diff --name-only`` reports,
using the data-driven tables below, and exposes ``should_run_exploits``.
It never reads file contents and never calls a model. The richer triage
module (owned by a separate task, future ``exhibit_a.triage``) is expected to
replace ``classify`` behind the same ``Classification`` shape.

Rules, first match wins per path, highest risk wins per PR:

- high: CI workflows and actions, dependency manifests and lock files,
  container files, and any path inside a sensitive directory.
- low: documentation and tests only.
- medium: everything else (ordinary application code).

An empty change list is low risk: there is nothing to analyse.

Usage from CI::

    git diff --name-only BASE...HEAD | python -m exhibit_a.ci.gate
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
from pathlib import PurePosixPath


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_ORDER = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2}


@dataclass(frozen=True)
class Rule:
    """One classification rule.

    ``paths`` are glob patterns matched against the whole normalised path,
    ``names`` against the lower-cased file name, and ``dirs`` against every
    lower-cased directory component.
    """

    risk: Risk
    reason: str
    paths: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    dirs: tuple[str, ...] = ()

    def matches(self, path: PurePosixPath) -> bool:
        text = path.as_posix()
        name = path.name.lower()
        parents = [part.lower() for part in path.parts[:-1]]
        return (
            any(fnmatchcase(text, pattern) for pattern in self.paths)
            or any(fnmatchcase(name, pattern) for pattern in self.names)
            or any(part in self.dirs for part in parents)
        )


#: Ordered rule table. High-risk rules come first so that, for example,
#: ``docs/requirements.txt`` is a dependency file, not documentation.
RULES: tuple[Rule, ...] = (
    Rule(
        Risk.HIGH,
        "CI workflow or action definition",
        paths=(".github/workflows/*", ".github/actions/*"),
        names=("action.yml", "action.yaml"),
    ),
    Rule(
        Risk.HIGH,
        "dependency manifest or lock file",
        names=(
            "requirements*.txt", "requirements*.in", "constraints*.txt",
            "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock",
            "poetry.lock", "uv.lock", "pdm.lock", "package.json",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        ),
    ),
    Rule(
        Risk.HIGH,
        "container definition",
        names=(
            "dockerfile", "dockerfile.*", "*.dockerfile", "containerfile",
            "docker-compose*.yml", "docker-compose*.yaml", "compose.yml",
            "compose.yaml", ".dockerignore",
        ),
    ),
    Rule(
        Risk.HIGH,
        "file in a sensitive directory",
        dirs=(
            ".github", "auth", "authn", "authz", "security", "crypto",
            "secrets", "permissions", "sandbox", "oracle", "middleware",
        ),
    ),
    Rule(
        Risk.LOW,
        "documentation",
        paths=("docs/*", "doc/*"),
        names=("*.md", "*.rst", "*.adoc", "license", "license.*", "notice", "authors"),
    ),
    Rule(
        Risk.LOW,
        "test code",
        paths=("tests/*", "test/*"),
        names=("test_*.py", "*_test.py", "conftest.py"),
        dirs=("tests", "test"),
    ),
)

_DEFAULT = Rule(Risk.MEDIUM, "application code")


@dataclass(frozen=True)
class Classification:
    """Risk of a pull request and, per path, the rule that decided it."""

    risk: Risk
    reasons: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "risk": self.risk.value,
            "should_run_exploits": should_run_exploits(self.risk),
            "reasons": dict(self.reasons),
        }


def _normalise(raw: str) -> PurePosixPath | None:
    text = raw.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    text = text.lstrip("/")
    if not text:
        return None
    return PurePosixPath(text)


def classify_path(path: str, rules: Sequence[Rule] = RULES) -> Rule:
    """Return the first rule that matches ``path`` (medium if none does)."""
    normalised = _normalise(path)
    if normalised is None:
        return _DEFAULT
    for rule in rules:
        if rule.matches(normalised):
            return rule
    return _DEFAULT


def classify(paths: Iterable[str], rules: Sequence[Rule] = RULES) -> Classification:
    """Classify a pull request from its changed paths (highest risk wins)."""
    risk = Risk.LOW
    reasons: dict[str, str] = {}
    for raw in paths:
        normalised = _normalise(raw)
        if normalised is None:
            continue
        rule = classify_path(raw, rules)
        reasons[normalised.as_posix()] = f"{rule.risk.value}: {rule.reason}"
        if _ORDER[rule.risk] > _ORDER[risk]:
            risk = rule.risk
    return Classification(risk, reasons)


def should_run_exploits(risk: Risk | str) -> bool:
    """Exploits run for medium and high risk; a docs/tests-only PR skips them."""
    return Risk(risk) is not Risk.LOW


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m exhibit_a.ci.gate",
        description="Classify a PR's risk from changed paths (one per line).",
    )
    parser.add_argument(
        "--files", default="-", help="File with one changed path per line (default: stdin)."
    )
    args = parser.parse_args(argv)
    if args.files == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(args.files, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    print(json.dumps(classify(lines).to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

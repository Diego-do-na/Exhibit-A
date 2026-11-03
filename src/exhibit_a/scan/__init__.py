from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from ..schemas import Baseline, Dependency, RepoProfile

MAX_READ_BYTES = 32 * 1024  # 32 KiB cap per file read
VENDORED_DIRS = {"node_modules", ".venv", "venv"}

#: Languages the proof loop can verify, for ``--lang`` and ``detect`` overrides.
LOOP_LANGUAGES = ("python", "javascript", "typescript")

#: File extensions counted as a language signal (capped walk, vendored dirs skipped).
EXTENSION_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "typescript",
}
MAX_COUNTED_FILES = 500
MAX_TEST_FILES = 80
CASE_LANGUAGE_KEYS = ("run.language", "language")
TEST_DIR_NAMES = frozenset({"tests", "test"})
PYTEST_CONFIG_NAMES = ("pytest.ini", ".pytest.ini", "pytest.toml")
PYTHON_MANIFEST_NAMES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "dev-requirements.txt",
    "test-requirements.txt",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "tox.ini",
)
_PYTEST_IMPORT_RE = re.compile(r"(?m)^[ \t]*(?:import pytest\b|from pytest(?:[ \t]+import|\.))")
_PYTEST_MARK_RE = re.compile(r"@pytest\.mark\b")
_UNITTEST_IMPORT_RE = re.compile(
    r"(?m)^[ \t]*(?:import unittest\b|from unittest(?:[ \t]+import|\.))"
)


def _safe_read(path: Path, repo_root: Path) -> str:
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return ""
    if not str(resolved).startswith(str(repo_root.resolve())):
        return ""
    for part in resolved.parts:
        if part in VENDORED_DIRS:
            return ""
    try:
        with resolved.open("rb") as fh:
            data = fh.read(MAX_READ_BYTES + 1)
    except OSError:
        return ""
    if len(data) > MAX_READ_BYTES:
        data = data[:MAX_READ_BYTES]
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _find_files(root: Path, names: Iterable[str]) -> List[Path]:
    found = []
    for name in names:
        p = root / name
        if p.exists():
            found.append(p)
    return found


@dataclass(frozen=True)
class ScanResult:
    profile: RepoProfile
    supported: bool
    reasons: list[str]
    languages: list[str]


def _case_language(root: Path) -> str:
    """The ``language`` a corpus ``case.json`` declares, or "" when none does.

    A case directory names its own language (``run.language``, else top-level
    ``language``); only the loop's languages count, anything else is untrusted
    data and ignored.
    """
    try:
        data = json.loads((root / "case.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    run = data.get("run")
    candidates = []
    if isinstance(run, dict):
        candidates.append(run.get("language"))
    candidates.append(data.get("language"))
    for candidate in candidates:
        if candidate in LOOP_LANGUAGES:
            return str(candidate)
    return ""


def _extension_languages(root: Path) -> list[str]:
    """Languages with source files under ``root``, most files first.

    A capped walk that skips vendored directories; symlinks are never followed.
    """
    counts: dict[str, int] = {}
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in VENDORED_DIRS and not d.startswith(".")]
        for name in filenames:
            language = EXTENSION_LANGUAGES.get(Path(name).suffix.lower())
            if language is None:
                continue
            counts[language] = counts.get(language, 0) + 1
            seen += 1
            if seen >= MAX_COUNTED_FILES:
                break
        if seen >= MAX_COUNTED_FILES:
            break
    return sorted(counts, key=lambda lang: (-counts[lang], lang))


def _text_names_pytest(text: str) -> bool:
    lower = text.lower()
    return (
        "pytest" in lower
        or "[tool.pytest" in lower
        or "[tool:pytest]" in lower
        or "[pytest]" in lower
    )


def _pytest_from_manifests(root: Path) -> bool:
    """True when config or dependency files name pytest."""
    for name in PYTEST_CONFIG_NAMES:
        path = root / name
        if path.is_file() and not path.is_symlink():
            return True
    extra: list[Path] = []
    req_dir = root / "requirements"
    if req_dir.is_dir() and not req_dir.is_symlink():
        extra.extend(
            sorted(child for child in req_dir.iterdir() if child.is_file() and child.suffix == ".txt")[:20]
        )
    for path in [*(root / name for name in PYTHON_MANIFEST_NAMES), *extra]:
        if _text_names_pytest(_safe_read(path, root)):
            return True
    return False


def _walk_test_python(root: Path):
    """Yield a capped set of test modules; never follows symlinks."""
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in VENDORED_DIRS and not d.startswith(".")]
        rel = Path(dirpath).relative_to(root)
        in_test_dir = bool(rel.parts and rel.parts[0] in TEST_DIR_NAMES)
        for name in filenames:
            if not name.endswith(".py"):
                continue
            if (
                name == "conftest.py"
                or name.startswith("test_")
                or name.endswith("_test.py")
                or in_test_dir
            ):
                yield Path(dirpath) / name
                seen += 1
                if seen >= MAX_TEST_FILES:
                    return
        if seen >= MAX_TEST_FILES:
            return


def _python_test_framework(root: Path) -> tuple[str, str]:
    """Return ``(framework, test_cmd)`` for a Python repository.

    Pytest wins on pytest.ini / ``[tool.pytest]``, requirements, pyproject,
    conftest.py, ``import pytest``, or ``@pytest.mark``. Otherwise unittest.
    """
    if _pytest_from_manifests(root):
        return "pytest", "pytest"
    saw_pytest = False
    saw_unittest = False
    for path in _walk_test_python(root):
        if path.name == "conftest.py":
            saw_pytest = True
        text = _safe_read(path, root)
        if _PYTEST_IMPORT_RE.search(text) or _PYTEST_MARK_RE.search(text):
            saw_pytest = True
        if _UNITTEST_IMPORT_RE.search(text):
            saw_unittest = True
        if saw_pytest:
            break
    if saw_pytest:
        return "pytest", "pytest"
    if saw_unittest:
        return "unittest", "python -m unittest"
    return "unittest", "python -m unittest"


def detect(repo_root: str, language: str = "auto") -> ScanResult:
    """Rule-based detection of language, package manager and test command.

    Signals, in order: project markers (``pyproject.toml``/``requirements.txt``,
    ``package.json``, ``tsconfig.json``, ``pom.xml``), a corpus ``case.json``
    language, then counted source-file extensions. ``language`` overrides the
    primary: ``"auto"`` detects, otherwise one of ``LOOP_LANGUAGES``; anything
    else raises ``ValueError``. The profile's ``language`` field always records
    the primary.
    """
    if language not in ("auto", *LOOP_LANGUAGES):
        raise ValueError(f"unknown language {language!r}; expected auto or one of {list(LOOP_LANGUAGES)}")
    root = Path(repo_root)
    reasons: list[str] = []
    dependency_manager = "unknown"
    install_cmd = "unknown"
    test_cmd = "unknown"
    framework = "unknown"
    interpreter = "unknown"

    detected: list[str] = []
    if any((root / n).exists() for n in ("pyproject.toml", "requirements.txt", "setup.cfg")):
        detected.append("python")
    if (root / "package.json").exists():
        detected.append("javascript")
    if (root / "tsconfig.json").exists():
        detected.append("typescript")
    if (root / "pom.xml").exists() or (root / "build.gradle").exists():
        detected.append("java")
    case_language = _case_language(root)
    if case_language and case_language not in detected:
        detected.append(case_language)
    for ext_language in _extension_languages(root):
        if ext_language not in detected:
            detected.append(ext_language)

    languages = detected or ["unknown"]
    if language != "auto":
        primary = language
        if primary not in detected:
            detected.append(primary)
            languages = detected
    else:
        # A declared case language wins over the package.json guess (a TypeScript
        # case still ships a package.json); otherwise python first, as before.
        if case_language:
            primary = case_language
        else:
            primary = next(
                (l for l in ("python", "typescript", "javascript", "java") if l in detected),
                "unknown",
            )

    if primary == "python":
        interpreter = "python3"
        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            txt = _safe_read(pyproject, root)
            if "tool.poetry" in txt:
                dependency_manager = "poetry"
                install_cmd = "poetry install"
            else:
                dependency_manager = "pip"
                install_cmd = "python -m pip install -r requirements.txt" if (root / "requirements.txt").exists() else "python -m pip install -e ."
        elif (root / "requirements.txt").exists():
            dependency_manager = "pip"
            install_cmd = "python -m pip install -r requirements.txt"
        else:
            dependency_manager = "pip"
            install_cmd = "python -m pip install -e ."

        framework, test_cmd = _python_test_framework(root)

        profile = RepoProfile(
            commit="unknown",
            language="python",
            interpreter=interpreter,
            dependency_manager=dependency_manager,
            install_cmd=install_cmd,
            test_cmd=test_cmd,
            framework=framework,
            dependencies=[],
            baseline=Baseline(passed=0, failed=0, seconds=0.0),
        )
        supported = framework == "pytest"
        if not supported:
            reasons.append("only pytest-run Python projects are supported in v1")
        return ScanResult(profile=profile, supported=supported, reasons=reasons, languages=languages)

    if primary in ("javascript", "typescript"):
        txt = _safe_read(root / "package.json", root)
        try:
            data = json.loads(txt) if txt else {}
        except Exception:
            data = {}
        if (root / "yarn.lock").exists():
            dependency_manager = "yarn"
            install_cmd = "yarn install"
        else:
            dependency_manager = "npm"
            install_cmd = "npm install --ignore-scripts"
        test_cmd = "node --test"
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if any(k.lower().startswith("jest") or k == "jest" for k in deps):
            framework = "jest"
        elif any("vitest" in k.lower() for k in deps):
            framework = "vitest"
        elif any("mocha" in k.lower() for k in deps):
            framework = "mocha"
        else:
            framework = "node:test"

        profile = RepoProfile(
            commit="unknown",
            language=primary,
            interpreter="node",
            dependency_manager=dependency_manager,
            install_cmd=install_cmd,
            test_cmd=test_cmd,
            framework=framework,
            dependencies=[],
            baseline=Baseline(passed=0, failed=0, seconds=0.0),
        )
        reasons.append("the proof loop verifies node:test repositories; only pytest-run Python projects count as scanner-supported")
        return ScanResult(profile=profile, supported=False, reasons=reasons, languages=languages)

    if primary == "java":
        dependency_manager = "maven" if (root / "pom.xml").exists() else "gradle"
        install_cmd = "mvn -DskipTests package" if (root / "pom.xml").exists() else "gradle build -x test"
        test_cmd = "mvn test" if (root / "pom.xml").exists() else "gradle test"
        framework = "junit"
        profile = RepoProfile(
            commit="unknown",
            language="java",
            interpreter="java",
            dependency_manager=dependency_manager,
            install_cmd=install_cmd,
            test_cmd=test_cmd,
            framework=framework,
            dependencies=[],
            baseline=Baseline(passed=0, failed=0, seconds=0.0),
        )
        reasons.append("scanner v1 supports only Python/pytest")
        return ScanResult(profile=profile, supported=False, reasons=reasons, languages=languages)

    profile = RepoProfile(
        commit="unknown",
        language="unknown",
        interpreter="unknown",
        dependency_manager="unknown",
        install_cmd="unknown",
        test_cmd="unknown",
        framework="unknown",
        dependencies=[],
        baseline=Baseline(passed=0, failed=0, seconds=0.0),
    )
    reasons.append("no recognizable project files")
    return ScanResult(profile=profile, supported=False, reasons=reasons, languages=languages)

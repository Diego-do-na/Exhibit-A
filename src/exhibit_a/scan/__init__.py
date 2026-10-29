from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..schemas import Baseline, Dependency, RepoProfile


MAX_READ_BYTES = 32 * 1024  # 32 KiB cap per file read
VENDORED_DIRS = {"node_modules", ".venv", "venv"}


def _safe_read(path: Path, repo_root: Path) -> str:
    """Read file with size cap and avoid symlinks escaping repo_root."""
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return ""
    if not str(resolved).startswith(str(repo_root.resolve())):
        return ""
    # skip vendored dirs
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


def _find_files(root: Path, names: Iterable[str]) -> list[Path]:
    found = []
    for name in names:
        p = root / name
        if p.exists():
            found.append(p)
    return found


def detect(repo_root: str) -> RepoProfile:
    """Rule-based detection of language, package manager and test command.

    This function reads repository files only (no subprocess), uses simple
    heuristics, and returns a RepoProfile object (placeholder baseline).
    """
    root = Path(repo_root)
    reasons: list[str] = []
    language = "unknown"
    dependency_manager = "unknown"
    install_cmd = "unknown"
    test_cmd = "unknown"
    framework = "unknown"
    interpreter = "unknown"

    # Python detection
    py_files = _find_files(root, ("pyproject.toml", "requirements.txt", "setup.cfg"))
    if py_files:
        language = "python"
        interpreter = "python3"
        # prefer pyproject/poetry
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

        # test framework detection
        # check requirements and pyproject for "pytest"
        maybe = ""
        for p in ("requirements.txt", "pyproject.toml", "setup.cfg"):
            maybe += _safe_read(root / p, root)
        if "pytest" in maybe:
            framework = "pytest"
            test_cmd = "pytest"
        else:
            framework = "unittest"
            test_cmd = "python -m unittest"

        # supported only when pytest detected
        supported = framework == "pytest"
        if not supported:
            reasons.append("only pytest-run Python projects are supported in v1")

        profile = RepoProfile(
            commit="unknown",
            language=language,
            interpreter=interpreter,
            dependency_manager=dependency_manager,
            install_cmd=install_cmd,
            test_cmd=test_cmd,
            framework=framework,
            dependencies=[],
            baseline=Baseline(passed=0, failed=0, seconds=0.0),
        )
        # encode notes into framework string when schema doesn't yet include supported/reasons
        if not supported:
            profile.framework = f"{framework} (unsupported: {'; '.join(reasons)})"
        return profile

    # JavaScript / TypeScript detection
    pkg = root / "package.json"
    if pkg.exists():
        language = "javascript"
        txt = _safe_read(pkg, root)
        try:
            data = json.loads(txt) if txt else {}
        except Exception:
            data = {}
        # package manager guess
        if (root / "yarn.lock").exists():
            dependency_manager = "yarn"
            install_cmd = "yarn install"
        else:
            dependency_manager = "npm"
            install_cmd = "npm install"
        # scripts test
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if scripts.get("test"):
            test_cmd = f"{dependency_manager} test"
        else:
            test_cmd = f"{dependency_manager} test"
        # framework detection via devDependencies or dependencies
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if any(k.lower().startswith("jest") or k == "jest" for k in deps):
            framework = "jest"
        elif any("vitest" in k.lower() for k in deps):
            framework = "vitest"
        elif any("mocha" in k.lower() for k in deps):
            framework = "mocha"
        else:
            framework = "npm"
        profile = RepoProfile(
            commit="unknown",
            language=language,
            interpreter="node",
            dependency_manager=dependency_manager,
            install_cmd=install_cmd,
            test_cmd=test_cmd,
            framework=f"{framework} (unsupported: scanner v1 supports only Python/pytest)",
            dependencies=[],
            baseline=Baseline(passed=0, failed=0, seconds=0.0),
        )
        return profile

    # Java detection
    if (root / "pom.xml").exists() or (root / "build.gradle").exists():
        language = "java"
        dependency_manager = "maven" if (root / "pom.xml").exists() else "gradle"
        install_cmd = "mvn -DskipTests package" if (root / "pom.xml").exists() else "gradle build -x test"
        test_cmd = "mvn test" if (root / "pom.xml").exists() else "gradle test"
        framework = "junit"
        profile = RepoProfile(
            commit="unknown",
            language=language,
            interpreter="java",
            dependency_manager=dependency_manager,
            install_cmd=install_cmd,
            test_cmd=test_cmd,
            framework=f"{framework} (unsupported: scanner v1 supports only Python/pytest)",
            dependencies=[],
            baseline=Baseline(passed=0, failed=0, seconds=0.0),
        )
        return profile

    # empty or unknown
    profile = RepoProfile(
        commit="unknown",
        language="unknown",
        interpreter="unknown",
        dependency_manager="unknown",
        install_cmd="unknown",
        test_cmd="unknown",
        framework="unknown (unsupported: no recognizable project files)",
        dependencies=[],
        baseline=Baseline(passed=0, failed=0, seconds=0.0),
    )
    return profile


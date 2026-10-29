from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from ..schemas import Baseline, Dependency, RepoProfile

MAX_READ_BYTES = 32 * 1024  # 32 KiB cap per file read
VENDORED_DIRS = {"node_modules", ".venv", "venv"}


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


def detect(repo_root: str) -> ScanResult:
    """Rule-based detection of language, package manager and test command."""
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
    if (root / "pom.xml").exists() or (root / "build.gradle").exists():
        detected.append("java")

    languages = detected or ["unknown"]
    primary = next((l for l in ("python", "javascript", "java") if l in detected), "unknown")

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

        maybe = ""
        for p in ("requirements.txt", "pyproject.toml", "setup.cfg"):
            maybe += _safe_read(root / p, root)
        if "pytest" in maybe:
            framework = "pytest"
            test_cmd = "pytest"
        else:
            framework = "unittest"
            test_cmd = "python -m unittest"

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

    if primary == "javascript":
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
            install_cmd = "npm install"
        test_cmd = f"{dependency_manager} test"
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
            language="javascript",
            interpreter="node",
            dependency_manager=dependency_manager,
            install_cmd=install_cmd,
            test_cmd=test_cmd,
            framework=framework,
            dependencies=[],
            baseline=Baseline(passed=0, failed=0, seconds=0.0),
        )
        reasons.append("scanner v1 supports only Python/pytest")
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

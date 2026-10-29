from pathlib import Path

import pytest

from exhibit_a.scan import detect


ROOT = Path(__file__).resolve().parent


def _case(path):
    return str(ROOT / "fixtures" / "scan" / path)


def test_detects_python_pyproject(tmp_path):
    repo = tmp_path / "py"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[tool.poetry]\nname = 'x'\n")
    (repo / "requirements.txt").write_text("pytest\n")
    profile = detect(str(repo))
    assert profile.language == "python"
    assert "pytest" in profile.test_cmd
    assert "poetry" in profile.dependency_manager or "pip" in profile.dependency_manager


def test_detects_javascript_package_json(tmp_path):
    repo = tmp_path / "js"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"x","devDependencies":{"jest":"^29.0.0"}}')
    profile = detect(str(repo))
    assert profile.language == "javascript"
    assert "jest" in profile.framework
    assert "npm" in profile.dependency_manager or "yarn" in profile.dependency_manager


def test_detects_java_pom(tmp_path):
    repo = tmp_path / "java"
    repo.mkdir()
    (repo / "pom.xml").write_text("<project></project>")
    profile = detect(str(repo))
    assert profile.language == "java"
    assert "junit" in profile.framework


def test_detects_monorepo(tmp_path):
    repo = tmp_path / "mono"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[tool.poetry]\n")
    (repo / "package.json").write_text('{"name":"x"}')
    # detection prefers python if python files present
    profile = detect(str(repo))
    assert profile.language in ("python", "javascript")


def test_empty_repo_returns_unknown(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    profile = detect(str(repo))
    assert profile.language == "unknown"
    assert "unsupported" in profile.framework


def test_no_subprocess_in_scan_module():
    import inspect
    import exhibit_a.scan as scanmod
    src = inspect.getsource(scanmod)
    # disallow importing or calling the subprocess module from the scanner
    assert "import subprocess" not in src
    assert "subprocess." not in src


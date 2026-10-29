from pathlib import Path

import pytest

from exhibit_a.scan import detect, ScanResult


ROOT = Path(__file__).resolve().parent


def _case(path):
    return str(ROOT / "fixtures" / "scan" / path)


def test_detects_python_pyproject(tmp_path):
    repo = tmp_path / "py"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[tool.poetry]\nname = 'x'\n")
    (repo / "requirements.txt").write_text("pytest\n")
    res = detect(str(repo))
    assert isinstance(res, ScanResult)
    profile = res.profile
    assert profile.language == "python"
    assert profile.framework == "pytest"
    assert res.supported is True
    assert "python" in res.languages


def test_detects_javascript_package_json(tmp_path):
    repo = tmp_path / "js"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"x","devDependencies":{"jest":"^29.0.0"}}')
    res = detect(str(repo))
    profile = res.profile
    assert profile.language == "javascript"
    assert profile.framework == "jest"
    assert res.supported is False
    assert res.reasons and len(res.reasons) >= 1
    assert "javascript" in res.languages


def test_detects_java_pom(tmp_path):
    repo = tmp_path / "java"
    repo.mkdir()
    (repo / "pom.xml").write_text("<project></project>")
    res = detect(str(repo))
    profile = res.profile
    assert profile.language == "java"
    assert profile.framework == "junit"
    assert res.supported is False
    assert "java" in res.languages


def test_detects_monorepo(tmp_path):
    repo = tmp_path / "mono"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[tool.poetry]\n")
    (repo / "package.json").write_text('{"name":"x"}')
    # detection prefers python if python files present; languages must list both
    res = detect(str(repo))
    profile = res.profile
    assert profile.language == "python"
    assert "python" in res.languages and "javascript" in res.languages
    # framework should be a clean value like 'pytest' or 'unittest'
    assert profile.framework in ("pytest", "unittest")
    assert isinstance(res.reasons, list)


def test_empty_repo_returns_unknown(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    res = detect(str(repo))
    profile = res.profile
    assert profile.language == "unknown"
    assert profile.framework == "unknown"
    assert res.supported is False
    assert res.reasons and len(res.reasons) >= 1


def test_no_subprocess_in_scan_module():
    import inspect
    import exhibit_a.scan as scanmod
    src = inspect.getsource(scanmod)
    # disallow importing or calling the subprocess module from the scanner
    assert "import subprocess" not in src
    assert "subprocess." not in src


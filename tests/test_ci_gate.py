"""Tests for the rule-based PR risk gate (exhibit_a.ci.gate)."""

from __future__ import annotations

import io
import json

import pytest

from exhibit_a.ci import gate
from exhibit_a.ci.gate import Risk, Rule, classify, classify_path, should_run_exploits


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        ".github/actions/setup/action.yml",
        "action.yml",
        "requirements.txt",
        "requirements-dev.txt",
        "docs/requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "setup.py",
        "Dockerfile",
        "docker/Dockerfile.prod",
        "deploy/app.dockerfile",
        "docker-compose.yml",
        "src/app/auth/login.py",
        "src/app/Security/tokens.py",
        "src/exhibit_a/sandbox/runner.py",
        "src/auth/README.md",
        ".github/CODEOWNERS",
    ],
)
def test_high_risk_paths(path: str) -> None:
    assert classify_path(path).risk is Risk.HIGH
    assert classify([path]).risk is Risk.HIGH


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "docs/guide.md",
        "docs/images/flow.png",
        "CHANGELOG.rst",
        "LICENSE",
        "tests/test_app.py",
        "tests/fixtures/data.json",
        "src/pkg/tests/helpers.py",
        "src/pkg/test_utils.py",
        "src/pkg/utils_test.py",
        "conftest.py",
    ],
)
def test_low_risk_paths(path: str) -> None:
    assert classify_path(path).risk is Risk.LOW


@pytest.mark.parametrize("path", ["src/app/views.py", "app.py", "web/index.js", "Makefile"])
def test_other_code_is_medium(path: str) -> None:
    assert classify_path(path).risk is Risk.MEDIUM


def test_highest_risk_wins() -> None:
    assert classify(["README.md", "tests/test_a.py"]).risk is Risk.LOW
    assert classify(["README.md", "src/app.py"]).risk is Risk.MEDIUM
    assert classify(["README.md", "src/app.py", "Dockerfile"]).risk is Risk.HIGH


def test_empty_change_list_is_low() -> None:
    assert classify([]).risk is Risk.LOW
    assert classify(["", "   "]).risk is Risk.LOW


def test_paths_are_normalised_and_reasons_recorded() -> None:
    result = classify(["./src/app.py", "/docs/a.md", "src\\auth\\x.py"])
    assert set(result.reasons) == {"src/app.py", "docs/a.md", "src/auth/x.py"}
    assert result.reasons["src/auth/x.py"].startswith("high:")
    assert result.risk is Risk.HIGH


def test_should_run_exploits() -> None:
    assert should_run_exploits(Risk.LOW) is False
    assert should_run_exploits(Risk.MEDIUM) is True
    assert should_run_exploits(Risk.HIGH) is True
    assert should_run_exploits("high") is True
    with pytest.raises(ValueError):
        should_run_exploits("critical")


def test_rules_are_data_driven() -> None:
    rules = (Rule(Risk.HIGH, "billing code", dirs=("billing",)),)
    assert classify(["src/billing/charge.py"], rules).risk is Risk.HIGH
    assert classify(["Dockerfile"], rules).risk is Risk.MEDIUM


def test_to_dict_and_cli(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("docs/a.md\nsrc/app.py\n"))
    assert gate.main([]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "medium"
    assert data["should_run_exploits"] is True
    assert data["reasons"]["src/app.py"] == "medium: application code"


def test_cli_reads_file(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    listing = tmp_path / "changed.txt"
    listing.write_text("tests/test_x.py\n", encoding="utf-8")
    assert gate.main(["--files", str(listing)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "risk": "low",
        "should_run_exploits": False,
        "reasons": {"tests/test_x.py": "low: test code"},
    }

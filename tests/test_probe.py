"""Tests for bench/probe.py with a fake provider: no model, no network."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.probe import (  # noqa: E402
    build_cases,
    main,
    probe_roles,
    render_markdown,
    write_summary,
)
from exhibit_a.models import Completion, Pricing, Role  # noqa: E402
from exhibit_a.models.config import PROVIDER_REGISTRY  # noqa: E402

VALID = {
    Role.ADVERSARY: '{"suspicions": []}',
    Role.TEST_WRITER: '{"test_source": "def test_x(): pass"}',
    Role.FIXER: '{"files": []}',
    Role.DEFENDER: '{"variants": []}',
}


class FakeProvider:
    """Stands in for a local model; serves one canned text per role."""

    name = "fake"

    def __init__(self, texts: dict[Role, str]):
        self.texts = texts
        self.calls = 0
        self.pricing = Pricing()

    def complete(self, role, prompt, schema):
        self.calls += 1
        return Completion(self.texts[role], 10, 5, 1, "fake-1")


def test_each_role_uses_its_real_prompt_and_schema():
    cases = build_cases()
    assert set(cases) == set(Role)
    markers = {
        Role.ADVERSARY: "ROLE: adversary",
        Role.TEST_WRITER: "ROLE: test_writer",
        Role.FIXER: "ROLE: fixer",
        Role.DEFENDER: "ROLE: defender",
    }
    required = {
        Role.ADVERSARY: "suspicions",
        Role.TEST_WRITER: "test_source",
        Role.FIXER: "files",
        Role.DEFENDER: "variants",
    }
    for role, (prompt, schema) in cases.items():
        assert markers[role] in prompt
        assert required[role] in schema["required"]
    prompts = [prompt for prompt, _ in cases.values()]
    assert len(set(prompts)) == len(prompts)  # one slice per role, not one blob


def test_all_valid_reports_full_rate():
    reports = probe_roles(FakeProvider(dict(VALID)), repeats=3)
    assert {r.role for r in reports} == {r.value for r in Role}
    assert all((r.valid, r.total, r.rate) == (3, 3, 1.0) for r in reports)


def test_garbage_reports_zero_rate():
    provider = FakeProvider({role: "not json at all {{{" for role in Role})
    reports = probe_roles(provider, repeats=2)
    assert all((r.valid, r.rate) == (0, 0.0) for r in reports)
    assert provider.calls == 2 * len(Role)


def test_rate_is_per_role_not_per_model():
    # Valid writer output satisfies only the writer schema.
    provider = FakeProvider(
        {role: '{"test_source": "def test_x(): pass"}' for role in Role}
    )
    rates = {r.role: r.rate for r in probe_roles(provider, repeats=2)}
    assert rates == {
        "adversary": 0.0,
        "test_writer": 1.0,
        "fixer": 0.0,
        "defender": 0.0,
    }


def test_repeats_must_be_positive():
    with pytest.raises(ValueError):
        probe_roles(FakeProvider(dict(VALID)), repeats=0)


def test_write_summary_writes_json_and_markdown(tmp_path):
    reports = probe_roles(FakeProvider(dict(VALID)), repeats=2)
    out = write_summary(
        reports, tmp_path / "probe", provider="fake", model="fake-1", repeats=2
    )
    payload = json.loads((out / "summary.json").read_text())
    assert payload["provider"] == "fake"
    assert payload["repeats"] == 2
    assert payload["roles"]["fixer"] == {"role": "fixer", "valid": 2, "total": 2, "rate": 1.0}
    table = (out / "summary.md").read_text()
    assert table.splitlines()[2] == "| role | valid | total | rate |"
    assert "| fixer | 2 | 2 | 1.00 |" in table
    assert render_markdown(reports, "fake", "fake-1", 2) == table


def test_main_writes_summary_through_registry(tmp_path):
    PROVIDER_REGISTRY["probe_fake"] = lambda spec: FakeProvider(dict(VALID))
    try:
        rc = main(
            ["--provider", "probe_fake", "--model", "fake-1",
             "--repeats", "2", "--out", str(tmp_path / "out")]
        )
    finally:
        del PROVIDER_REGISTRY["probe_fake"]
    assert rc == 0
    payload = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert payload["model"] == "fake-1"
    assert all(role["rate"] == 1.0 for role in payload["roles"].values())

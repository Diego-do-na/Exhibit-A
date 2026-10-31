"""Tests for the real-CVE benchmark (bench/realcve.py and its manifest).

* manifest schema: every entry links its advisory, versions differ, the
  harness exists and declares its entry point (checked by AST, no import);
* harness import check (docker): every harness imports against both the
  vulnerable and the fixed version in the sandbox, with no model involved;
* table generation from a fake results file;
* budget stop with a fake provider: the first BudgetExceeded stops every
  later reading without another pipeline call.
"""

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.realcve import (  # noqa: E402
    EFFECTS,
    MANIFEST_PATH,
    REALCVE_DIR,
    load_manifest,
    render_table,
    requirements_for,
    run_live,
    write_results,
)
from exhibit_a.models import BudgetExceeded  # noqa: E402


@pytest.fixture(scope="module")
def manifest():
    return load_manifest()


@pytest.fixture(scope="module")
def entries(manifest):
    return manifest["entries"]


def test_manifest_has_at_least_twelve_entries(entries):
    assert len(entries) >= 12


def test_manifest_entries_link_advisories(entries):
    by_id = {}
    for entry in entries:
        assert entry["id"] not in by_id, f"duplicate id {entry['id']}"
        by_id[entry["id"]] = entry
        assert entry["vulnerable_version"] != entry["fixed_version"]
        assert entry["effect"] in EFFECTS
        assert entry["advisories"], f"{entry['id']}: no advisories"
        for advisory in entry["advisories"]:
            url = advisory["url"]
            assert url.startswith(("https://", "http://")), f"{entry['id']}: bad url {url!r}"
        harness = REALCVE_DIR / entry["harness"]
        assert harness.is_file(), f"{entry['id']}: harness missing"


def test_manifest_harnesses_declare_their_entry_point(entries):
    for entry in entries:
        source = (REALCVE_DIR / entry["harness"]).read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert entry["entry_point"] in names, (
            f"{entry['id']}: entry point {entry['entry_point']!r} not defined"
        )


def test_manifest_rejects_bad_entries(tmp_path):
    base = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    good = base["entries"][0]
    assert good["vulnerable_version"] != good["fixed_version"]

    def write(entries):
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps({"version": 1, "entries": entries}), encoding="utf-8")
        return path

    with pytest.raises(ValueError):
        load_manifest(write([]))
    same = dict(good, fixed_version=good["vulnerable_version"])
    with pytest.raises(ValueError):
        load_manifest(write([same]))
    bad_effect = dict(good, id="x", effect="canary_mindread")
    with pytest.raises(ValueError):
        load_manifest(write([bad_effect]))
    dup = [good, dict(good)]
    with pytest.raises(ValueError):
        load_manifest(write(dup))
    missing = dict(good, id="y", harness="harnesses/nope/app.py")
    with pytest.raises(ValueError):
        load_manifest(write([missing]))


def test_requirements_pin_both_versions(entries):
    entry = next(e for e in entries if e["id"] == "starlette-cve-2023-29159")
    assert requirements_for(entry, "vulnerable") == ["starlette==0.26.1", "anyio>=3.4,<5"]
    assert requirements_for(entry, "fixed") == ["starlette==0.27.0", "anyio>=3.4,<5"]
    plain = next(e for e in entries if e["id"] == "aiohttp-cve-2024-23334")
    assert requirements_for(plain, "vulnerable") == ["aiohttp==3.9.1"]


@pytest.mark.docker
def test_harness_imports_against_both_versions(entries):
    """Every harness imports in the sandbox under both pins (no model)."""
    from bench.realcve import check_import

    failures = []
    for entry in entries:
        for version in ("vulnerable", "fixed"):
            report = check_import(entry, version)
            if not report["ok"]:
                failures.append(f"{entry['id']} ({version}): {report['detail'][-300:]}")
    assert not failures, "harness imports failed:\n" + "\n".join(failures)


def _fake_rows():
    return [
        {
            "id": "starlette-cve-2023-29159",
            "cve": "CVE-2023-29159",
            "package": "starlette",
            "class": "path_traversal",
            "effect": "canary_read",
            "status": "ok",
            "vulnerable": {"version": "0.26.1", "proven": True, "cost_usd": 0.12, "tokens": 1200},
            "fixed": {"version": "0.27.0", "proven": False, "cost_usd": 0.10, "tokens": 1000},
        },
        {
            "id": "pygments-cve-2021-27291",
            "cve": "CVE-2021-27291",
            "package": "pygments",
            "class": "redos",
            "effect": "pending",
            "status": "pending",
        },
    ]


def test_table_generation_from_fake_results(tmp_path):
    table = render_table(_fake_rows())
    assert "| CVE | package | class | vulnerable: proven? | fixed: false proof? | cost (USD) | tokens |" in table
    assert "| CVE-2023-29159 | starlette | path_traversal | yes | no proof | 0.2200 | 2200 |" in table
    assert "| CVE-2021-27291 | pygments | redos | pending effect | pending effect | - | - |" in table

    out = write_results(
        _fake_rows(), provider="fake", model="fake-1.0",
        profile="compact", runs=1, out_dir=tmp_path,
    )
    assert out.name.startswith("realcve-") and out.suffix == ".json"
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["provider"] == "fake"
    assert [row["id"] for row in payload["entries"]] == [
        "starlette-cve-2023-29159", "pygments-cve-2021-27291",
    ]


def _two_entries():
    manifest = load_manifest()
    implemented = [e for e in manifest["entries"] if e["effect"] != "pending"]
    return implemented[:2]


def test_budget_stop_with_fake_provider(tmp_path):
    """The first BudgetExceeded stops every later reading with no more calls."""
    calls: list[tuple[str, str]] = []

    def pipeline(entry, version):
        calls.append((entry["id"], version))
        raise BudgetExceeded("budget of $0.0001 reached (spent $0.0002)")

    rows = run_live(
        _two_entries(), provider="fake", model="fake-1.0", profile="compact",
        runs=1, total_usd=0.0001, out_dir=tmp_path, pipeline=pipeline,
    )
    assert calls and len(calls) == 1
    first, second = rows
    assert first["vulnerable"]["status"] == "stopped"
    assert first["fixed"]["status"] == "stopped"
    assert first["status"] == "stopped"
    assert second["vulnerable"]["status"] == "stopped"
    assert second["fixed"]["status"] == "stopped"


def test_pending_entries_never_run(tmp_path):
    """Pending-effect entries are listed, and the pipeline never runs them."""
    manifest = load_manifest()
    pending = [e for e in manifest["entries"] if e["effect"] == "pending"]
    assert pending, "manifest needs at least one pending-effect entry"

    def pipeline(entry, version):  # pragma: no cover - must never run
        raise AssertionError(f"pending entry ran: {entry['id']}")

    rows = run_live(
        pending[:2], provider="fake", model="fake-1.0", profile="compact",
        runs=1, total_usd=1.0, out_dir=tmp_path, pipeline=pipeline,
    )
    assert [row["status"] for row in rows] == ["pending"] * len(rows)

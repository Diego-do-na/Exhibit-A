"""T109: proven dependency vulnerabilities (OSV advisory -> graph reachability -> proof -> upgrade).

Most tests are offline: synthetic repositories that call a fake library (``fakelib``) the
repository does not contain, hand-authored OSV records (labelled as such, never copies of a
real record), and no network. The proof-loop tests without Docker run the oracle on the
host through an injected test runner, like ``tests/test_audit.py``; the CLI never does that.
The Starlette end-to-end check is marked ``docker``: it installs starlette 0.26.1 and
0.27.0 from PyPI and judges the exploit in the sandbox, with a scripted fake provider.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.advisory import RecordedOsvBackend
from exhibit_a.advisory.deps_report import discover, prove_reachable, render_table, scan, write_report
from exhibit_a.advisory.graph_reach import dependency_reach, is_test_file, match_symbol
from exhibit_a.advisory.proof import advisory_block, rewrite_pin, upgrade_plan
from exhibit_a.advisory.symbols import SymbolInfo, affected_symbols
from exhibit_a.advisory.osv import parse_advisory
from exhibit_a.cli import main as cli_main
from exhibit_a.graph import build_graph
from exhibit_a.loop import Roles
from exhibit_a.models import Completion, ModelRole, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import run_oracle
from exhibit_a.schemas.advisory import DepsReport

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "bench" / "corpus"
STARLETTE = CORPUS / "starlette-cve-2023-29159"
STARLETTE_FIXED = CORPUS / "starlette-cve-2023-29159-fixed"

# -- hand-authored OSV records (test fixtures, NOT copies of any real record) -------------------

STARLETTE_ADVISORY = {
    "id": "GHSA-v5gw-mw7f-84px",
    "aliases": ["CVE-2023-29159"],
    "summary": "Starlette has a path traversal vulnerability in StaticFiles",
    "details": "Hand-authored test fixture. StaticFiles in starlette from 0.13.5 up to, not including, "
               "0.27.0 can serve a file from a sibling directory whose name starts with the served "
               "directory's name.",
    "modified": "2023-06-01T00:00:00Z",
    "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-22"]},
    "affected": [{
        "package": {"name": "starlette", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.13.5"}, {"fixed": "0.27.0"}]}],
    }],
    "references": [{"type": "ADVISORY",
                    "url": "https://github.com/encode/starlette/security/advisories/GHSA-v5gw-mw7f-84px"}],
}


def _fake_advisory(symbols_block: dict | None = None, *, key: str = "ecosystem_specific",
                   advisory_id: str = "FAKE-2026-0001", cwe: str = "CWE-22") -> dict:
    affected = {
        "package": {"name": "fakelib", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}],
    }
    if symbols_block is not None:
        affected[key] = symbols_block
    return {
        "id": advisory_id, "aliases": [], "summary": "fakelib reads files outside its base directory",
        "details": "Hand-authored test fixture for a library that does not exist.",
        "modified": "2026-01-01T00:00:00Z", "database_specific": {"severity": "HIGH", "cwe_ids": [cwe]},
        "affected": [affected],
    }


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


APP_CALLS_LIBRARY = {
    "requirements.txt": "fakelib==1.0\n",
    "app.py": (
        "import fakelib.pages\n\n\n"
        "class App:\n"
        "    def __init__(self, root):\n"
        "        self.root = root\n\n"
        "    def handle_request(self, name):\n"
        "        return render(self.root, name)\n\n\n"
        "def render(root, name):\n"
        "    return fakelib.pages.read_page(root, name)\n"
    ),
}

APP_IMPORTS_BUT_NEVER_CALLS = {
    "requirements.txt": "fakelib==1.0\n",
    "app.py": (
        "import fakelib.pages\n"
        "from fakelib.pages import read_page\n\n\n"
        "class App:\n"
        "    def handle_request(self, name):\n"
        "        return fakelib.pages.escape(name)\n"
    ),
}

APP_CALL_NOT_FROM_ENTRY = {
    "requirements.txt": "fakelib==1.0\n",
    "app.py": (
        "import fakelib.pages\n\n\n"
        "class App:\n"
        "    def handle_request(self, name):\n"
        "        return name.upper()\n\n\n"
        "def maintenance(root):\n"
        "    return fakelib.pages.read_page(root, 'index.html')\n"
    ),
}

READ_PAGE = {"affected_functions": ["fakelib.pages.read_page"]}


def _backend(*records: dict) -> RecordedOsvBackend:
    return RecordedOsvBackend(list(records), label="test-fixture")


def _only(report: DepsReport):
    assert len(report.advisories) == 1, report.advisories
    return report.advisories[0]


# -- reachability on synthetic repositories ---------------------------------------------------

def test_entry_point_reaches_the_library_function(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    item = _only(scan(repo, _backend(_fake_advisory(READ_PAGE))).report)
    reach = item.reachability
    assert reach.status == "reachable"
    assert reach.symbol_source == "osv_ecosystem_specific"
    path = reach.paths[0]
    assert path.kind == "call"
    assert path.entry == "app:App.handle_request" and path.oracle_entry_point == "App.handle_request"
    assert path.nodes == ["app:App.handle_request", "app:render"]
    assert path.use.target == "fakelib.pages.read_page" and path.use.file == "app.py"
    assert path.confidence == 1.0
    assert "App.handle_request -> render -> fakelib.pages.read_page (app.py:13)" == path.rendered
    assert item.effect == "canary_read" and item.vuln_class == "path_traversal"
    assert item.fixed_in == "1.1" and item.proof.status == "not_attempted"


def test_imported_but_never_called_function_is_not_reachable(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_IMPORTS_BUT_NEVER_CALLS)
    item = _only(scan(repo, _backend(_fake_advisory(READ_PAGE))).report)
    reach = item.reachability
    assert reach.status == "not_reachable"
    assert reach.paths == [] and reach.uses == []
    assert reach.package_imported and "app.py:1" in reach.import_sites
    assert "imported" in reach.reason and "fakelib.pages.read_page" in reach.reason
    # The graph says what it cannot see instead of claiming safety.
    assert any("dynamic dispatch" in spot for spot in reach.blind_spots)


def test_call_that_no_entry_point_reaches_is_not_reachable(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_CALL_NOT_FROM_ENTRY)
    reach = _only(scan(repo, _backend(_fake_advisory(READ_PAGE))).report).reachability
    assert reach.status == "not_reachable"
    assert [u.node for u in reach.uses] == ["app:maintenance"]
    assert "no entry point reaches" in reach.reason


def test_advisory_without_symbols_is_unknown(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    item = _only(scan(repo, _backend(_fake_advisory(None))).report)
    assert item.reachability.status == "unknown"
    assert item.reachability.symbol_source == "none"
    assert "names no affected symbol" in item.reachability.reason


def test_database_specific_imports_shape_is_read(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    block = {"imports": [{"path": "fakelib.pages", "symbols": ["read_page"]}]}
    reach = _only(scan(repo, _backend(_fake_advisory(block, key="database_specific"))).report).reachability
    assert reach.symbol_source == "osv_database_specific"
    assert reach.symbols == ["fakelib.pages.read_page"] and reach.status == "reachable"


def test_symbol_map_matches_by_alias_and_carries_the_served_entry() -> None:
    record = dict(STARLETTE_ADVISORY, id="PYSEC-TEST-0001")  # only the alias is known to the map
    info = affected_symbols(parse_advisory(record), "starlette")
    assert info.source == "symbol_map"
    assert "starlette.staticfiles.StaticFiles" in info.symbols
    assert info.served_entry == "StaticFiles.__call__" and info.effect == "canary_read"


def test_symbol_matching_is_by_dotted_prefix_not_by_text() -> None:
    assert match_symbol("starlette.staticfiles.StaticFiles.lookup_path",
                        ["starlette.staticfiles.StaticFiles"]) == "starlette.staticfiles.StaticFiles"
    assert match_symbol("starlette.staticfiles.StaticFilesX", ["starlette.staticfiles.StaticFiles"]) is None
    assert is_test_file("tests/helpers.py") and is_test_file("baseline_test.py")
    assert not is_test_file("app/contest.py")


@pytest.mark.parametrize("app_source", [
    # Starlette: a route table built with Mount(app=StaticFiles(...)).
    "from starlette.applications import Starlette\n"
    "from starlette.routing import Mount\n"
    "from starlette.staticfiles import StaticFiles\n\n\n"
    "def create_app(directory):\n"
    "    return Starlette(routes=[Mount('/static', app=StaticFiles(directory=directory), name='static')])\n",
    # FastAPI: app.mount(...) on a module-level application, through FastAPI's re-export.
    "from fastapi import FastAPI\n"
    "from fastapi.staticfiles import StaticFiles\n\n"
    "app = FastAPI()\n"
    "app.mount('/static', StaticFiles(directory='static'), name='static')\n",
])
def test_mounted_static_files_are_served_by_the_framework(tmp_path, app_source) -> None:
    repo = _write(tmp_path / "repo", {"requirements.txt": "starlette==0.26.1\n", "app.py": app_source})
    item = _only(scan(repo, _backend(STARLETTE_ADVISORY)).report)
    reach = item.reachability
    assert reach.status == "reachable", reach.reason
    path = reach.paths[0]
    assert path.kind == "served" and path.oracle_entry_point == "StaticFiles.__call__"
    assert path.use.mounted and path.confidence == 1.0
    assert "[framework dispatch] StaticFiles.__call__" in path.rendered
    assert item.severity_label == "MODERATE"


def test_static_files_built_but_never_mounted_is_not_reachable(tmp_path) -> None:
    repo = _write(tmp_path / "repo", {
        "requirements.txt": "starlette==0.26.1\n",
        "app.py": "from starlette.staticfiles import StaticFiles\n\nFILES = StaticFiles(directory='static')\n",
    })
    reach = _only(scan(repo, _backend(STARLETTE_ADVISORY)).report).reachability
    assert reach.status == "not_reachable"
    assert reach.uses and reach.uses[0].context == "module_level" and not reach.uses[0].mounted


def test_vendored_copy_of_the_library_is_followed(tmp_path) -> None:
    repo = _write(tmp_path / "repo", {
        "requirements.txt": "fakelib==1.0\n",
        "fakelib/__init__.py": "",
        "fakelib/pages.py": "def read_page(root, name):\n    return open(root + '/' + name).read()\n",
        "server.py": (
            "from fakelib.pages import read_page\n\n\n"
            "def app(scope, receive, send):\n"
            "    return read_page('/srv', scope['path'])\n"
        ),
    })
    reach = _only(scan(repo, _backend(_fake_advisory(READ_PAGE))).report).reachability
    assert reach.status == "reachable"
    kinds = {p.kind for p in reach.paths}
    assert "vendored" in kinds
    vendored = next(p for p in reach.paths if p.kind == "vendored")
    assert vendored.entry == "server:app" and vendored.nodes[-1] == "fakelib.pages:read_page"


# -- the Starlette corpus case ---------------------------------------------------------------------

def test_starlette_corpus_case_reads_case_json_and_counts_test_entries_only_on_request() -> None:
    inputs = discover(STARLETTE)
    assert [(d.name, d.version) for d in inputs.dependencies] == [("starlette", "0.26.1")]
    assert inputs.unsupported and inputs.unsupported[0].text.startswith("anyio")
    default = _only(scan(STARLETTE, _backend(STARLETTE_ADVISORY)).report).reachability
    # The case holds no application, only its baseline test: test code is not an entry point.
    assert default.status == "not_reachable" and "only in test code" in default.reason
    with_tests = _only(scan(STARLETTE, _backend(STARLETTE_ADVISORY), include_tests=True).report).reachability
    assert with_tests.status == "reachable"
    assert with_tests.paths[0].entry_kind == "test"
    assert with_tests.paths[0].use.target == "starlette.staticfiles.StaticFiles"


def test_starlette_027_is_not_affected() -> None:
    report = scan(STARLETTE_FIXED, _backend(STARLETTE_ADVISORY)).report
    assert [(d.name, d.version) for d in report.dependencies] == [("starlette", "0.27.0")]
    assert report.advisories == [] and report.counts.advisories == 0


# -- CLI and deps.json -------------------------------------------------------------------------------

def test_cli_writes_deps_json_and_calls_no_model_without_prove(tmp_path, capsys, monkeypatch) -> None:
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    fixture = tmp_path / "osv.json"
    fixture.write_text(json.dumps({"vulns": [_fake_advisory(READ_PAGE)]}), encoding="utf-8")
    import exhibit_a.cli.ext.deps as deps_ext

    def boom(args, meter):  # pragma: no cover - must never run without --prove
        raise AssertionError("a model role was built without --prove")

    monkeypatch.setattr(deps_ext, "_build_roles", boom)
    out = tmp_path / "out"
    rc = cli_main(["deps", "--repo", str(repo), "--offline", str(fixture), "--out", str(out)])
    assert rc == 0
    text = capsys.readouterr().out
    header = text.splitlines()[0]
    for column in ("ADVISORY", "PACKAGE VERSION", "SEVERITY", "REACHABLE?", "PROVEN?", "FIXED BY"):
        assert column in header
    assert "FAKE-2026-0001" in text and "fakelib 1.0" in text and "yes (1 path)" in text
    assert "upgrade to 1.1" in text and "never safe" in text
    data = json.loads((out / "deps.json").read_text(encoding="utf-8"))
    report = DepsReport.model_validate(data)
    assert report.schema_version == "1" and report.kind == "exhibit_a.deps"
    assert report.prove.requested is False and report.counts.reachable == 1
    assert report.advisories[0].reachability.paths[0].oracle_entry_point == "App.handle_request"


def test_cli_prove_requires_a_budget(tmp_path, capsys) -> None:
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    assert cli_main(["deps", "--repo", str(repo), "--prove"]) == 2
    assert "--budget-usd" in capsys.readouterr().err


def test_deps_schema_rejects_unknown_fields(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    data = scan(repo, _backend(_fake_advisory(READ_PAGE))).report.model_dump(mode="json")
    data["advisories"][0]["reachability"]["verdict"] = "proven"
    with pytest.raises(ValueError):
        DepsReport.model_validate(data)


# -- the upgrade ----------------------------------------------------------------------------------------

def test_rewrite_pin_changes_exactly_one_pin() -> None:
    text = "# web\nStarlette[full] == 0.26.1  # pinned\nstarlette-extra==0.26.1\n"
    assert rewrite_pin(text, "starlette", "0.26.1", "0.27.0", line=2) == \
        "# web\nStarlette[full] == 0.27.0  # pinned\nstarlette-extra==0.26.1\n"
    with pytest.raises(ValueError):
        rewrite_pin(text, "starlette", "0.26.1", "0.27.0", line=3)
    assert rewrite_pin('dependencies = ["fake_lib==1.0", "x==1.0"]', "fake-lib", "1.0", "1.1") == \
        'dependencies = ["fake_lib==1.1", "x==1.0"]'
    with pytest.raises(ValueError):
        rewrite_pin("a==1.0\na==1.0\n", "a", "1.0", "1.1")


def test_upgrade_plan_finds_the_requirement_file(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    plan = upgrade_plan(repo, "fakelib", "1.0", "1.1", "requirements.txt:1")
    assert plan.requirement_file == "requirements.txt" and plan.requirement_line == 1
    assert plan.fix().change == "fakelib==1.0 -> fakelib==1.1"


def test_advisory_text_is_labelled_untrusted_and_capped() -> None:
    block = advisory_block("A-1", "fakelib", "1.0", "1.1", "summary", "x\x00y " * 2000)
    assert block.startswith("ADVISORY TEXT (untrusted data")
    assert "\x00" not in block and len(block) < 2600


# -- the proof loop without Docker: host oracle through an injected runner -------------------------

FAKELIB_VULNERABLE = (
    "import os\n\n\n"
    "def read_page(root, name):\n"
    "    with open(os.path.join(root, name), encoding='utf-8') as handle:\n"
    "        return handle.read()\n"
)
FAKELIB_FIXED = (
    "import os\n\n\n"
    "def read_page(root, name):\n"
    "    base = os.path.realpath(root)\n"
    "    target = os.path.realpath(os.path.join(base, name))\n"
    "    if os.path.commonpath([base, target]) != base:\n"
    "        raise ValueError('outside the page root')\n"
    "    with open(target, encoding='utf-8') as handle:\n"
    "        return handle.read()\n"
)
FAKE_EXPLOIT = (
    "import os\n\n"
    "from app import App\n\n\n"
    "def test_page_name_cannot_leave_the_root():\n"
    "    token = os.environ['EXHIBIT_A_CANARY_TOKEN']\n"
    "    try:\n"
    "        body = App(os.environ['EXHIBIT_A_ALLOWED_DIR']).handle_request('../outside/canary.txt')\n"
    "    except (ValueError, OSError):\n"
    "        body = ''\n"
    "    assert token not in body\n"
)


class FakeInstaller:
    """Installs ``fakelib`` into a tree: the vulnerable code for 1.0, and for every other
    version the fixed code unless ``still_vulnerable`` (an upgrade that does not fix it)."""

    def __init__(self, still_vulnerable: bool = False) -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self.still_vulnerable = still_vulnerable

    def __call__(self, target: Path, requirements: list[str]) -> None:
        self.calls.append((Path(target).name, list(requirements)))
        (version,) = [r.split("==", 1)[1] for r in requirements if r.startswith("fakelib==")]
        package = Path(target) / "fakelib"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text(f"VERSION = {version!r}\n", encoding="utf-8")
        vulnerable = version == "1.0" or self.still_vulnerable
        (package / "pages.py").write_text(FAKELIB_VULNERABLE if vulnerable else FAKELIB_FIXED, encoding="utf-8")


class HostOracleRunner:
    """Test-only: baseline with pytest and the exploit under the host oracle. No Docker."""

    def __init__(self, requirements: tuple[str, ...]) -> None:
        self.requirements = requirements

    def run_baseline(self, clone, test_path, timeout):
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(test_path)],
            cwd=clone, capture_output=True, timeout=timeout,
            env={"PATH": os.environ["PATH"], "PYTHONPATH": str(clone), "PYTHONDONTWRITEBYTECODE": "1"},
        )
        return {"outcome": "passed" if proc.returncode == 0 else "failed", "exit_code": proc.returncode,
                "stdout": "", "stderr": "", "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect)


class ScriptedProvider:
    """A fake provider: fixed answers per role, every prompt kept for inspection."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self, suspicion: dict, exploit: str, *, edits: list | None = None,
                 variants: list | None = None, cost_usd: float = 0.0) -> None:
        self.suspicion, self.exploit, self.edits = suspicion, exploit, edits
        self.variants = variants or []
        self.cost_usd = cost_usd
        self.prompts: dict[Role, list[str]] = {}

    def complete(self, role, prompt, schema):
        self.prompts.setdefault(role, []).append(prompt)
        if role == Role.ADVERSARY:
            body = {"suspicions": [self.suspicion]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": self.exploit}
        elif role == Role.FIXER:
            body = {"edits": self.edits} if self.edits else {"edits": []}
        else:
            body = {"variants": self.variants}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted", cost_usd=self.cost_usd)


def _roles(provider):
    def factory(meter):
        return Roles(*(ModelRole(role, provider, meter) for role in
                       (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    return factory


FAKE_SUSPICION = {
    "id": "fakelib-read-page", "class": "path_traversal", "location": {"file": "app.py", "line": 13},
    "entry_point": "App.handle_request", "hypothesis": "read_page joins the name onto the root unchecked",
    "source": "name",
}


def _prove_fake(tmp_path, *, installer, provider, runners: list | None = None):
    repo = _write(tmp_path / "repo", APP_CALLS_LIBRARY)
    result = scan(repo, _backend(_fake_advisory(READ_PAGE)))

    def runner_factory(requirements):
        if runners is not None:
            runners.append(requirements)
        return HostOracleRunner(requirements)

    out = tmp_path / "out"
    report = prove_reachable(result, repo, out, _roles(provider), budget_usd=5.0, profile="compact",
                             installer=installer, runner_factory=runner_factory, runs=1, timeout=60)
    return repo, out, report


def test_reachable_advisory_is_proven_through_the_app_and_the_upgrade_is_verified(tmp_path) -> None:
    provider = ScriptedProvider(FAKE_SUSPICION, FAKE_EXPLOIT)
    installer, runners = FakeInstaller(), []
    repo, out, report = _prove_fake(tmp_path, installer=installer, provider=provider, runners=runners)
    item = _only(report)
    proof = item.proof
    assert proof.status == "proven", proof.reason
    assert proof.entry_point == "App.handle_request" and proof.effect == "canary_read"
    assert proof.upgrade_verified and proof.app_fix_proposed is False and proof.app_fix_verified is None
    assert proof.upgrade.change == "fakelib==1.0 -> fakelib==1.1"
    assert item.fixed_by == "upgrade to 1.1 (verified)" and report.counts.proven == 1
    # The vulnerable version went into the clone, the fixed one into the upgraded tree, and the
    # sandbox images were asked for the matching pins.
    assert installer.calls == [("clone", ["fakelib==1.0"]), ("fixed", ["fakelib==1.1"])]
    assert runners == [("fakelib==1.1",), ("fakelib==1.0",)]
    patch = (out / proof.package / "fix.patch").read_text(encoding="utf-8")
    assert "-fakelib==1.0" in patch and "+fakelib==1.1" in patch
    assert (repo / "requirements.txt").read_text(encoding="utf-8") == "fakelib==1.0\n"  # repo untouched
    # The advisory reached the models only as labelled, untrusted context.
    assert "ADVISORY TEXT (untrusted data" in provider.prompts[Role.ADVERSARY][0]
    assert "ENTRY POINT 1: App.handle_request" in provider.prompts[Role.ADVERSARY][0]
    assert "ADVISORY TEXT (untrusted data" in provider.prompts[Role.TEST_WRITER][0]
    write_report(report, out)
    assert DepsReport.model_validate_json((out / "deps.json").read_text(encoding="utf-8")).counts.proven == 1
    assert "PROVEN" in render_table(report)


def test_an_upgrade_that_does_not_stop_the_exploit_is_not_a_proof(tmp_path) -> None:
    provider = ScriptedProvider(FAKE_SUSPICION, FAKE_EXPLOIT)
    _, _, report = _prove_fake(tmp_path, installer=FakeInstaller(still_vulnerable=True), provider=provider)
    proof = _only(report).proof
    assert proof.status == "not_proven"
    assert proof.verdict == "discarded_unproven"
    assert "no verified fix" in proof.reason and "fakelib==1.1" in proof.reason
    assert not proof.upgrade_verified and _only(report).fixed_by == "upgrade to 1.1 (not verified)"


def test_an_exploit_that_calls_the_library_directly_is_not_a_proof(tmp_path) -> None:
    direct = FAKE_EXPLOIT.replace("from app import App", "from fakelib.pages import read_page").replace(
        "App(os.environ['EXHIBIT_A_ALLOWED_DIR']).handle_request('../outside/canary.txt')",
        "read_page(os.environ['EXHIBIT_A_ALLOWED_DIR'], '../outside/canary.txt')")
    provider = ScriptedProvider(FAKE_SUSPICION, direct)
    _, _, report = _prove_fake(tmp_path, installer=FakeInstaller(), provider=provider)
    proof = _only(report).proof
    assert proof.status == "not_proven" and proof.verdict == "invalid_test"


def test_app_level_fix_is_verified_on_top_of_the_upgrade_and_may_not_touch_the_library(tmp_path) -> None:
    edits = [
        {"path": "app.py", "find": "        return render(self.root, name)",
         "replace": "        if '..' in name:\n            raise ValueError(name)\n        return render(self.root, name)"},
        {"path": "fakelib/pages.py", "find": "import os", "replace": "import os  # edited"},
    ]
    provider = ScriptedProvider(FAKE_SUSPICION, FAKE_EXPLOIT, edits=edits)
    _, out, report = _prove_fake(tmp_path, installer=FakeInstaller(), provider=provider)
    proof = _only(report).proof
    assert proof.status == "proven", proof.reason
    assert proof.upgrade_verified and proof.app_fix_proposed and proof.app_fix_verified is True
    patch = (out / proof.package / "fix.patch").read_text(encoding="utf-8")
    assert "+fakelib==1.1" in patch and "raise ValueError(name)" in patch
    assert "fakelib/pages.py" not in patch  # the fixer may not edit the installed library


def test_unreachable_and_unknown_advisories_are_not_run(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_IMPORTS_BUT_NEVER_CALLS)
    result = scan(repo, _backend(_fake_advisory(READ_PAGE), _fake_advisory(None, advisory_id="FAKE-2")))

    class Untouchable:
        def __getattr__(self, name):  # pragma: no cover - any use is a failure
            raise AssertionError("no role may be used")

    report = prove_reachable(result, repo, tmp_path / "out", lambda meter: Untouchable(), budget_usd=1.0,
                             installer=FakeInstaller(), runner_factory=HostOracleRunner)
    assert [a.proof.status for a in report.advisories] == ["skipped", "skipped"]
    assert "not_reachable" in report.advisories[0].proof.reason
    assert "unknown" in report.advisories[1].proof.reason
    assert report.prove.requested and report.counts.proven == 0


# -- Starlette end to end in the sandbox --------------------------------------------------------

STARLETTE_APP = (
    "from starlette.applications import Starlette\n"
    "from starlette.routing import Mount\n"
    "from starlette.staticfiles import StaticFiles\n\n\n"
    "def create_app(directory):\n"
    "    return Starlette(routes=[Mount('/static', app=StaticFiles(directory=directory), name='static')])\n"
)
STARLETTE_EXPLOIT_TEMPLATE = '''\
import asyncio
import os
from pathlib import Path

from starlette.exceptions import HTTPException

from app import create_app


def get(asgi, path):
    scope = {
        "type": "http", "method": "GET", "path": path, "raw_path": path.encode(),
        "query_string": b"", "headers": [], "root_path": "", "scheme": "http",
        "server": ("testserver", 80), "client": ("testclient", 5000),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    try:
        asyncio.run(asgi(scope, receive, send))
    except HTTPException:
        return b""
    return b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def test_mounted_static_files_do_not_serve_a_sibling_directory():
    work = Path(os.environ["EXHIBIT_A_ALLOWED_DIR"]).parent
    token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
    served = work / "out"
    served.mkdir(exist_ok=True)
    app = create_app(str(served))
    static = next(route.app for route in app.routes if getattr(route, "path", "") == "/static")
    assert token.encode() not in get(static, "%s")
'''


@pytest.mark.docker
def test_starlette_0261_advisory_is_reachable_and_proven_in_the_sandbox(tmp_path) -> None:
    repo = _write(tmp_path / "repo", {"requirements.txt": "starlette==0.26.1\n", "app.py": STARLETTE_APP})
    result = scan(repo, _backend(STARLETTE_ADVISORY))
    item = _only(result.report)
    assert item.reachability.status == "reachable"
    assert item.reachability.paths[0].oracle_entry_point == "StaticFiles.__call__"
    suspicion = {
        "id": "starlette-staticfiles-commonprefix", "class": "path_traversal",
        "location": {"file": "app.py", "line": 7}, "entry_point": "StaticFiles.__call__",
        "hypothesis": "the mounted StaticFiles checks containment with a character prefix",
        "source": "scope['path']",
    }
    variants = [{"name": "dot-segment", "test_source": STARLETTE_EXPLOIT_TEMPLATE % "/./../outside/./canary.txt"}]
    provider = ScriptedProvider(suspicion, STARLETTE_EXPLOIT_TEMPLATE % "/../outside/canary.txt",
                                variants=variants)
    out = tmp_path / "out"
    report = prove_reachable(result, repo, out, _roles(provider), budget_usd=1.0, profile="compact",
                             runs=1, timeout=180)  # real pip installer and SandboxRunner
    proof = _only(report).proof
    assert proof.status == "proven", proof.reason
    assert proof.entry_point == "StaticFiles.__call__"
    assert proof.upgrade_verified and proof.upgrade.change == "starlette==0.26.1 -> starlette==0.27.0"
    assert _only(report).fixed_by == "upgrade to 0.27.0 (verified)"
    assert (out / proof.package / "verdict.json").is_file()
    shutil.rmtree(out / "deps", ignore_errors=True)

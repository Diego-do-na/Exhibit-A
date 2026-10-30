"""The opt-in compact prompt profile (--profile compact) and its cost controls.

The compact profile exists to cut output tokens, which dominate the cost of reasoning
models. These tests pin three things: the standard profile is byte-for-byte unchanged
(every recorded replay key hashes its prompts and schemas), the compact answers are
bounded, and the fixer's search/replace edits are treated as untrusted input.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.cli import main
from exhibit_a.cli.run import COMPACT_MAX_OUTPUT_TOKENS, _generation
from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop, prompts
from exhibit_a.models import Completion, ModelRole, Role
from exhibit_a.models import openai_compat
from exhibit_a.models.config import RoleConfig, build_roles
from exhibit_a.models.cost import Pricing
from exhibit_a.models.errors import ProviderError
from exhibit_a.models.jsonschema import SchemaValidationError, validate
from exhibit_a.oracle import run_oracle
from exhibit_a.schemas import Suspicion

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
ENTRY = "App.handle_request"
SUSPICION = {
    "id": "S1", "class": "path_traversal", "location": {"file": "app.py", "line": 4},
    "entry_point": ENTRY, "hypothesis": "h", "source": "q",
}


# -- the standard profile must not move ----------------------------------------------------

def _standard_snapshot() -> str:
    s = Suspicion.model_validate(SUSPICION)
    parts = [
        prompts.adversary_prompt("SRC", "app.py"),
        prompts.writer_prompt(s, "SRC"),
        prompts.fixer_prompt(s, "SRC", "EXP", "R"),
        prompts.defender_prompt(s, "PATCHED", "EXP"),
        json.dumps([prompts.SUSPICIONS_SCHEMA, prompts.EXPLOIT_SCHEMA, prompts.FIX_SCHEMA,
                    prompts.VARIANTS_SCHEMA], sort_keys=True),
    ]
    return "\n".join(parts) + "\n"


def test_standard_prompts_and_schemas_are_frozen():
    # Replay keys hash role + prompt + schema (models/replay.py). If this fails, every
    # recorded run (including the Meta recordings) stops replaying: do not update the hash,
    # put the change in a new profile instead.
    digest = hashlib.sha256(_standard_snapshot().encode()).hexdigest()
    assert digest == "adaf7325d34a416ce6bd999fef861af854b2a90961ac089435fda552b52bc6eb"


def test_standard_profile_is_the_original_builders():
    std = prompts.profile("standard")
    assert std.adversary_prompt is prompts.adversary_prompt
    assert std.fix_schema is prompts.FIX_SCHEMA
    assert std.fix_format == "files"


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="unknown prompt profile"):
        prompts.profile("cheap")


# -- compact answers are bounded -----------------------------------------------------------

def test_compact_suspicions_are_capped_in_number_and_length():
    schema = prompts.COMPACT_SUSPICIONS_SCHEMA
    validate({"suspicions": [SUSPICION] * 3}, schema)
    with pytest.raises(SchemaValidationError):
        validate({"suspicions": [SUSPICION] * 4}, schema)
    with pytest.raises(SchemaValidationError):
        validate({"suspicions": [{**SUSPICION, "hypothesis": "x" * 201}]}, schema)


def test_compact_fix_schema_wants_edits_not_files():
    schema = prompts.COMPACT_FIX_SCHEMA
    validate({"edits": [{"path": "app.py", "find": "a", "replace": "b"}]}, schema)
    with pytest.raises(SchemaValidationError):
        validate({"files": [{"path": "app.py", "content": "x"}]}, schema)
    with pytest.raises(SchemaValidationError):
        validate({"edits": []}, schema)


def test_compact_prompts_put_the_source_first_and_ask_for_brevity():
    s = Suspicion.model_validate(SUSPICION)
    for text in (
        prompts.compact_adversary_prompt("SRC", "app.py"),
        prompts.compact_writer_prompt(s, "SRC"),
        prompts.compact_fixer_prompt(s, "SRC", "EXP", "R"),
    ):
        assert text.startswith("SOURCE (app.py):\nSRC\n")
        assert "no prose" in text
    assert prompts.compact_defender_prompt(s, "PATCHED", "EXP").startswith("PATCHED SOURCE (app.py):\nPATCHED\n")
    assert '"edits"' in prompts.compact_fixer_prompt(s, "SRC", "EXP", "R")


# -- the fixer's edits are untrusted ---------------------------------------------------------

def _loop(tmp_path, profile="compact", roles=None):
    clone = tmp_path / "clone"
    if not clone.exists():
        shutil.copytree(FIXTURES / "vulnerable", clone)
    return VerificationLoop(clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), roles,
                            "test_baseline.py", run_id="r1", runner=HostRunner(), prompt_profile=profile)


def test_edits_become_whole_files(tmp_path):
    loop = _loop(tmp_path)
    original = (loop.clone / "app.py").read_text()
    line = original.splitlines()[0]
    files = loop._edits_to_files([
        {"path": "app.py", "find": line, "replace": line + "  # one"},
        {"path": "app.py", "find": line + "  # one", "replace": line + "  # two"},  # sees the first edit
    ])
    assert files == [{"path": "app.py", "content": original.replace(line, line + "  # two", 1)}]


@pytest.mark.parametrize("edit, message", [
    ({"path": "app.py", "find": "no such text anywhere", "replace": "x"}, "occurs 0 times"),
    ({"path": "app.py", "find": "", "replace": "x"}, "empty find"),
    ({"path": "new_module.py", "find": "a", "replace": "b"}, "not an existing file"),
    ({"path": "../app.py", "find": "a", "replace": "b"}, "invalid fix path"),
    ({"path": "/etc/passwd", "find": "root", "replace": "b"}, "invalid fix path"),
    ({"path": "", "find": "a", "replace": "b"}, "invalid fix path"),
])
def test_bad_edits_are_rejected(tmp_path, edit, message):
    with pytest.raises(ValueError, match=message):
        _loop(tmp_path)._edits_to_files([edit])


def test_two_spellings_of_one_path_are_one_file(tmp_path):
    loop = _loop(tmp_path)
    original = (loop.clone / "app.py").read_text()
    line = original.splitlines()[0]
    files = loop._edits_to_files([
        {"path": "app.py", "find": line, "replace": line + "  # one"},
        {"path": "./app.py", "find": line + "  # one", "replace": line + "  # two"},
    ])
    assert files == [{"path": "app.py", "content": original.replace(line, line + "  # two", 1)}]


def test_an_ambiguous_find_is_rejected(tmp_path):
    loop = _loop(tmp_path)
    (loop.clone / "dup.py").write_text("x = 1\nx = 1\n")
    with pytest.raises(ValueError, match="occurs 2 times"):
        loop._edits_to_files([{"path": "dup.py", "find": "x = 1", "replace": "x = 2"}])


def test_an_edit_through_a_symlink_is_rejected(tmp_path):
    loop = _loop(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1\n")
    (loop.clone / "link.py").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        loop._edits_to_files([{"path": "link.py", "find": "secret", "replace": "x"}])
    assert outside.read_text() == "secret = 1\n"


def test_too_many_edits_are_rejected(tmp_path):
    loop = _loop(tmp_path)
    line = (loop.clone / "app.py").read_text().splitlines()[0]
    with pytest.raises(ValueError, match="too many edits"):
        loop._edits_to_files([{"path": "app.py", "find": line, "replace": line}] * 11)


# -- end to end: the compact loop proves, fixes with edits and verifies -----------------------

BASELINE_TEST = '''\
from app import create_app


def test_known_file_is_served(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "/download", {"name": "a.txt"}).body == "hello"
'''

TRAVERSAL = '''\
import os
from app import create_app


def test_download_cannot_escape_base_dir():
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
    response = app.handle_request("GET", "/download", {"name": "%s"})
    assert token not in response.body
'''


def _minimal_edits(before: str, after: str) -> list[dict[str, str]]:
    """Search/replace edits that turn ``before`` into ``after``, each find unique."""
    a, b = before.splitlines(keepends=True), after.splitlines(keepends=True)
    edits = []
    for tag, i1, i2, j1, j2 in reversed(difflib.SequenceMatcher(None, a, b).get_opcodes()):
        if tag == "equal":
            continue
        lo, hi = i1, i2
        while True:  # widen with context until the find text is unique
            lo, hi = max(lo - 1, 0), min(hi + 1, len(a))
            find = "".join(a[lo:hi])
            if before.count(find) == 1:
                break
        replace = "".join(a[lo:i1]) + "".join(b[j1:j2]) + "".join(a[i2:hi])
        edits.append({"path": "app.py", "find": find, "replace": replace})
    return edits


class CompactScripted:
    name = "scripted"
    pricing = Pricing()

    def __init__(self):
        self.schemas = {}

    def complete(self, role, prompt, schema):
        self.schemas[role] = schema
        if role == Role.ADVERSARY:
            body = {"suspicions": [SUSPICION | {"id": "S-PROVEN", "location": {"file": "app.py", "line": 45},
                                                "hypothesis": "name is joined to base_dir unchecked",
                                                "source": "query['name']"}]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": TRAVERSAL % "../outside/canary.txt"}
        elif role == Role.FIXER:
            before = (FIXTURES / "vulnerable" / "app.py").read_text()
            after = (FIXTURES / "fixed" / "app.py").read_text()
            body = {"edits": _minimal_edits(before, after)}
        else:
            body = {"variants": [{"name": "dot-segment", "test_source": TRAVERSAL % "./../outside/./canary.txt"}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


class HostRunner:
    def run_baseline(self, clone, test_path, timeout):
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": clone, "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path],
                              cwd=clone, env=env, capture_output=True, timeout=timeout)
        return {"outcome": "passed" if proc.returncode == 0 else "failed", "exit_code": proc.returncode,
                "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode(), "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect)


def test_compact_loop_proves_and_verifies_a_fix_made_of_edits(tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    (clone / "test_baseline.py").write_text(BASELINE_TEST)
    provider = CompactScripted()
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    loop = VerificationLoop(clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), roles,
                            "test_baseline.py", run_id="r1", runner=HostRunner(), prompt_profile="compact")
    result = loop.run("app.py")
    proven = next(r for r in result.results if r.suspicion.id == "S-PROVEN")
    assert proven.verdict.verdict == "proven"
    assert proven.fix_verified
    assert "+        base = os.path.realpath" in (proven.package_dir / "fix.patch").read_text()
    assert provider.schemas[Role.FIXER] is prompts.COMPACT_FIX_SCHEMA
    assert provider.schemas[Role.ADVERSARY] is prompts.COMPACT_SUSPICIONS_SCHEMA


# -- provider cost controls ------------------------------------------------------------------

def _capture(monkeypatch, reply):
    sent = {}

    def fake_post_json(url, body, headers, timeout):
        sent["url"], sent["body"] = url, body
        return reply

    monkeypatch.setattr(openai_compat, "post_json", fake_post_json)
    monkeypatch.setenv("TEST_KEY", "k")
    return sent


OK_REPLY = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}, "model": "m"}


def test_no_cost_controls_means_the_request_body_is_unchanged(monkeypatch):
    sent = _capture(monkeypatch, OK_REPLY)
    openai_compat.OpenAICompatibleProvider("https://x/v1", "m", "TEST_KEY").complete(Role.ADVERSARY, "p", {})
    assert set(sent["body"]) == {"model", "messages", "response_format"}


def test_cost_controls_are_sent_when_configured(monkeypatch):
    sent = _capture(monkeypatch, OK_REPLY)
    provider = openai_compat.OpenAICompatibleProvider("https://x/v1", "m", "TEST_KEY",
                                                      reasoning_effort="minimal", max_output_tokens=6000)
    provider.complete(Role.ADVERSARY, "p", {})
    assert sent["body"]["reasoning_effort"] == "minimal"
    assert sent["body"]["max_tokens"] == 6000


def test_an_unknown_effort_or_a_negative_cap_is_rejected():
    with pytest.raises(ValueError, match="unknown reasoning effort"):
        openai_compat.OpenAICompatibleProvider("https://x/v1", "m", "K", reasoning_effort="tiny")
    with pytest.raises(ValueError, match=">= 0"):
        openai_compat.OpenAICompatibleProvider("https://x/v1", "m", "K", max_output_tokens=-1)


def test_an_answer_cut_by_the_cap_is_a_clear_provider_error(monkeypatch):
    _capture(monkeypatch, {"choices": [{"message": {"content": None}, "finish_reason": "length"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 50}})
    provider = openai_compat.OpenAICompatibleProvider("https://x/v1", "m", "TEST_KEY", max_output_tokens=50)
    with pytest.raises(ProviderError, match="output-token cap"):
        provider.complete(Role.ADVERSARY, "p", {})


def test_role_config_carries_the_controls_to_the_meta_provider():
    roles = build_roles({Role.FIXER: RoleConfig(provider="meta", model="muse-wonder-1.0",
                                                reasoning_effort="low", max_output_tokens=123)})
    provider = roles[Role.FIXER].provider
    assert (provider.reasoning_effort, provider.max_output_tokens) == ("low", 123)


# -- CLI -------------------------------------------------------------------------------------

def _args(**kw):
    return argparse.Namespace(**{"profile": "standard", "reasoning_effort": None, "max_output_tokens": None} | kw)


def test_standard_profile_sends_no_controls_by_default():
    assert _generation(_args(), Role.FIXER) == {"reasoning_effort": "", "max_output_tokens": 0}


def test_compact_profile_defaults_to_minimal_effort_and_role_caps():
    for role in Role:
        assert _generation(_args(profile="compact"), role) == {
            "reasoning_effort": "minimal", "max_output_tokens": COMPACT_MAX_OUTPUT_TOKENS[role]}


def test_explicit_flags_win_over_the_profile():
    assert _generation(_args(profile="compact", reasoning_effort="low", max_output_tokens=0), Role.ADVERSARY) == {
        "reasoning_effort": "low", "max_output_tokens": 0}


def test_an_old_namespace_without_the_new_flags_still_works():
    assert _generation(argparse.Namespace(), Role.ADVERSARY) == {"reasoning_effort": "", "max_output_tokens": 0}


def test_compact_cannot_replay_the_standard_recordings(tmp_path, capsys):
    case = tmp_path / "case.json"
    case.write_text("{}")
    assert main(["run", "--case", str(case), "--replay", "--profile", "compact"]) == 2
    assert "cannot be combined with --replay" in capsys.readouterr().err


# -- the compact proof contract ----------------------------------------------------------------

def test_the_read_contract_says_where_the_canary_is_and_what_is_forbidden():
    text = prompts.test_contract("canary_read", ["starlette==0.26.1", "anyio>=3.4,<5"])
    assert "'outside', 'canary.txt'" in text
    assert "EXHIBIT_A_CANARY_TOKEN" in text and "NOT in the application's response" in text
    for forbidden in ("monkeypatch", "ctypes", "subprocess"):
        assert forbidden in text
    assert "starlette==0.26.1, anyio>=3.4,<5" in text
    assert "EXHIBIT_A_CANARY'" not in text  # the canary's own variable is not part of the contract (A-11 F2)


def test_the_write_contract_asks_the_application_to_create_the_canary():
    text = prompts.test_contract("canary_write")
    assert "creates that file" in text and "assert not os.path.exists" in text
    assert "nothing beyond the application itself" in text


def test_an_unknown_effect_has_no_contract():
    with pytest.raises(ValueError, match="unknown oracle effect"):
        prompts.test_contract("canary_delete")


class ContractSpy(CompactScripted):
    def __init__(self):
        super().__init__()
        self.prompts = {}

    def complete(self, role, prompt, schema):
        self.prompts[role] = prompt
        return super().complete(role, prompt, schema)


def test_the_compact_loop_sends_the_contract_with_the_case_packages(tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    (clone / "test_baseline.py").write_text(BASELINE_TEST)
    spy = ContractSpy()
    roles = Roles(*(ModelRole(r, spy) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    loop = VerificationLoop(clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), roles,
                            "test_baseline.py", run_id="r1", runner=HostRunner(),
                            requirements=("example-pkg==1.0",), prompt_profile="compact")
    loop.run("app.py")
    for role in (Role.TEST_WRITER, Role.DEFENDER):
        assert "PROOF CONTRACT" in spy.prompts[role]
        assert "example-pkg==1.0" in spy.prompts[role]


def test_the_standard_loop_never_sends_the_contract(tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    (clone / "test_baseline.py").write_text(BASELINE_TEST)
    spy = ContractSpy()
    roles = Roles(*(ModelRole(r, spy) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    loop = VerificationLoop(clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), roles,
                            "test_baseline.py", run_id="r1", runner=HostRunner(), prompt_profile="standard")
    loop.run("app.py")  # the compact answers fail the standard fixer schema; only prompts matter here
    assert "PROOF CONTRACT" not in spy.prompts[Role.TEST_WRITER]


# -- recording compact runs (bench/record_meta.py) ---------------------------------------------

def test_compact_recordings_never_overwrite_the_standard_ones():
    from bench.record_meta import DEFAULT_MODEL, recording_paths

    standard = recording_paths("starlette-cve-2023-29159", DEFAULT_MODEL)
    compact = recording_paths("starlette-cve-2023-29159", DEFAULT_MODEL, "compact")
    assert standard[0].name == f"meta-{DEFAULT_MODEL}.jsonl"  # the T070 file names are unchanged
    assert compact[0].name == f"meta-{DEFAULT_MODEL}-compact.jsonl"
    assert compact[1].name == f"meta-{DEFAULT_MODEL}-compact.json"
    with pytest.raises(ValueError, match="unknown profile"):
        recording_paths("starlette-cve-2023-29159", DEFAULT_MODEL, "cheap")


def test_record_meta_accepts_the_profile_flag_and_still_needs_the_key(monkeypatch, capsys):
    from bench.record_meta import main as record_main

    monkeypatch.delenv("META_API_KEY", raising=False)
    assert record_main(["--profile", "compact", "--case", "archive-extraction-pathtraversal"]) == 2
    assert "META_API_KEY is not set" in capsys.readouterr().err


# -- entry points --------------------------------------------------------------------------------

@pytest.mark.parametrize("raw, name", [
    ("App.handle_request", "App.handle_request"),
    ("App.handle_request(POST, blob)", "App.handle_request"),  # seen in the 2026-10-30 compact run
    ("StaticFiles.__call__ -> get_path -> lookup_path", "StaticFiles.__call__"),  # same run
    ("  download_file  ", "download_file"),
    ("-> nothing", "-> nothing"),  # no leading name: unchanged, matches no frame
])
def test_canonical_entry_point_keeps_only_the_leading_dotted_name(raw, name):
    assert prompts.canonical_entry_point(raw) == name


def test_the_compact_loop_judges_with_the_canonical_entry_point(tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    (clone / "test_baseline.py").write_text(BASELINE_TEST)

    class Decorated(CompactScripted):
        def complete(self, role, prompt, schema):
            if role == Role.ADVERSARY:
                s = SUSPICION | {"id": "S-PROVEN", "location": {"file": "app.py", "line": 45},
                                 "entry_point": "App.handle_request(GET, /download, name)"}
                return Completion(json.dumps({"suspicions": [s]}), 10, 10, 1, model="scripted")
            return super().complete(role, prompt, schema)

    seen = []

    class Recording(HostRunner):
        def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
            seen.append(set(entry_points))
            return super().run_exploit(app_root, test_path, entry_points, timeout=timeout, effect=effect)

    provider = Decorated()
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    loop = VerificationLoop(clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), roles,
                            "test_baseline.py", run_id="r1", runner=Recording(), prompt_profile="compact")
    result = loop.run("app.py")
    assert seen and all(s == {ENTRY} for s in seen)
    assert result.results[0].verdict.verdict == "proven"


def test_the_standard_profile_keeps_the_entry_point_as_written():
    assert not prompts.profile("standard").canonical_entry_points

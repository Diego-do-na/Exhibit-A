"""Tests for the GitHub Action wiring (action.yml) and its workflow template.

The Action must drive the real PR-diff surface (``exhibit-a run
--pr-diff BASE..HEAD``), map the CLI exit codes, refuse to stay green when
the surface did not run, and keep every existing security property
(permissions, fork handling, key scoping, leak scan). These tests parse the
YAML files instead of running the workflows, so they need no Docker, no
network and no secrets. See docs/reference/cli-exit-codes.md and docs/security/audit-integration.md
(findings F8 and F11).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_YML = REPO_ROOT / "action.yml"
WORKFLOW_YML = REPO_ROOT / ".github" / "workflows" / "exhibit-a.yml"

SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _load_action() -> dict:
    return yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))


def _load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW_YML.read_text(encoding="utf-8"))


def _step(action: dict, name: str) -> dict:
    for step in action["runs"]["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"step {name!r} not found in action.yml")


def _run_scripts(action: dict) -> list[str]:
    return [step.get("run", "") for step in action["runs"]["steps"]]


# -- PR-diff surface -----------------------------------------------------------


def test_engine_passes_pr_diff_with_base_and_head() -> None:
    engine = _step(_load_action(), "Run Exhibit A")["run"]
    assert "--pr-diff" in engine
    assert '"$base..$head"' in engine
    # The old placeholder surface must be gone from the engine invocation.
    assert "$OUT/run/pr.diff" not in engine
    assert re.search(r"(?:^|\s)--diff(?:\s|$)", engine) is None


def test_engine_reads_base_and_head_shas_from_inputs_or_event() -> None:
    engine_step = _step(_load_action(), "Run Exhibit A")
    env = engine_step["env"]
    assert env["IN_BASE_SHA"] == "${{ inputs.base-sha }}"
    assert env["IN_HEAD_SHA"] == "${{ inputs.head-sha }}"
    assert "EVENT_BASE_SHA" in env and "pull_request.base.sha" in env["EVENT_BASE_SHA"]
    assert "EVENT_HEAD_SHA" in env and "pull_request.head.sha" in env["EVENT_HEAD_SHA"]
    action = _load_action()
    assert "head-sha" in action["inputs"]
    assert action["inputs"]["head-sha"]["default"] == ""


def test_base_and_head_shas_validated_as_40_hex() -> None:
    engine = _step(_load_action(), "Run Exhibit A")["run"]
    assert engine.count("^[0-9a-f]{40}$") >= 2
    assert "base-sha must be a full commit SHA" in engine
    assert "head-sha must be a full commit SHA" in engine


def test_shas_never_interpolated_into_shell_unquoted() -> None:
    engine = _step(_load_action(), "Run Exhibit A")["run"]
    assert "$base..$head" not in engine.replace('"$base..$head"', "")
    for script in _run_scripts(_load_action()):
        assert "${{" not in script


def test_engine_passes_provider_and_model_from_inputs() -> None:
    engine_step = _step(_load_action(), "Run Exhibit A")
    assert engine_step["env"]["IN_PROVIDER"] == "${{ inputs.provider }}"
    assert engine_step["env"]["IN_MODEL"] == "${{ inputs.model }}"
    run = engine_step["run"]
    assert '--provider "$IN_PROVIDER"' in run
    assert '--model "$IN_MODEL"' in run


# -- exit-code mapping (docs/reference/cli-exit-codes.md) --------------------------------


def test_engine_maps_cli_exit_codes() -> None:
    engine = _step(_load_action(), "Run Exhibit A")["run"]
    # 0 ran clean, 10 ran with a proven finding, 124/137 are the timeout
    # wrapper: all three continue to the summary. 20 (incomplete) and
    # 2 (usage/input error, e.g. an unsupported provider) fail here.
    assert "0|10|124|137" in engine
    for code in ("20", "2"):
        assert code in engine
    assert "engine-exit=$code" in engine
    failing = [line for line in engine.splitlines() if "exit 1" in line]
    assert len(failing) >= 3  # 20, 2, and unexpected codes


def test_proven_finding_can_still_fail_the_check() -> None:
    gate = _step(_load_action(), "Gate on proven findings")["run"]
    assert 'EXIT_CODE != "0"' in gate or "EXIT_CODE" in gate
    assert "exit 1" in gate


# -- surface_ran / not_run must never pass -------------------------------------


def test_summary_fails_when_the_surface_did_not_run() -> None:
    summary = _step(_load_action(), "Write summary and result JSON")["run"]
    assert "surface_ran" in summary
    assert "result.json" in summary
    assert "did not run" in summary
    assert "exit 1" in summary
    # A skipped risk-gate run legitimately has no events.
    assert "skipped" in summary


def test_not_run_status_never_passes_the_gate() -> None:
    gate = _step(_load_action(), "Gate on proven findings")["run"]
    assert "not_run" in gate
    assert "exit 1" in gate


# -- audit F8: case mode --------------------------------------------------------


def test_case_mode_requires_replay() -> None:
    setup = _step(_load_action(), "Validate inputs and install Exhibit A")["run"]
    assert "IN_CASE" in _step(_load_action(), "Validate inputs and install Exhibit A")["env"]
    assert 'case runs require replay' in setup
    assert "exit 1" in setup or "fail " in setup


def test_key_is_not_exported_on_the_case_path() -> None:
    engine = _step(_load_action(), "Run Exhibit A")["run"]
    assert 'if [[ -n "$IN_CASE" ]]' in engine
    assert 'key=""' in engine


# -- preserved security properties ----------------------------------------------


def test_key_leak_scan_still_covers_run_output() -> None:
    engine = _step(_load_action(), "Run Exhibit A")["run"]
    assert "grep" in engine and "found in the run output" in engine
    assert "unset EXHIBIT_A_API_KEY" in engine


def test_no_step_interpolates_untrusted_values_into_scripts() -> None:
    for script in _run_scripts(_load_action()):
        assert "${{" not in script


# -- workflow template ----------------------------------------------------------


def test_workflow_stays_inert_unless_enabled() -> None:
    workflow = _load_workflow()
    for job in ("verify", "fork-guard"):
        condition = workflow["jobs"][job]["if"]
        assert "EXHIBIT_A_ENABLED" in condition


def test_workflow_does_not_use_pull_request_target() -> None:
    workflow = _load_workflow()
    triggers = workflow.get("on", workflow.get(True, {}))
    assert "pull_request_target" not in triggers
    assert "pull_request" in triggers


def test_workflow_checkout_is_pinned_to_a_full_sha() -> None:
    workflow = _load_workflow()
    checkout = next(
        step
        for step in workflow["jobs"]["verify"]["steps"]
        if "actions/checkout@" in step.get("uses", "")
    )
    ref = checkout["uses"].split("@", 1)[1]
    assert SHA40.match(ref), f"checkout is not SHA-pinned: {checkout['uses']}"


def test_workflow_keeps_minimal_permissions_and_fork_guard() -> None:
    workflow = _load_workflow()
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["verify"]["permissions"]["contents"] == "read"
    guard = "\n".join(
        str(step.get("run", "")) for step in workflow["jobs"]["fork-guard"]["steps"]
    )
    assert "exit 1" in guard


def test_action_third_party_steps_are_pinned_to_full_shas() -> None:
    action = _load_action()
    for step in action["runs"]["steps"]:
        uses = step.get("uses", "")
        if uses.startswith("actions/"):
            ref = uses.split("@", 1)[1]
            assert SHA40.match(ref), f"{step.get('name')}: {uses} is not SHA-pinned"


# -- live PR demo wiring (T089) -------------------------------------------------


def test_profile_input_is_validated_and_passed_to_the_engine() -> None:
    action = _load_action()
    profile = action["inputs"]["profile"]
    assert profile["default"] == "standard"
    setup = _step(action, "Validate inputs and install Exhibit A")
    assert setup["env"]["IN_PROFILE"] == "${{ inputs.profile }}"
    assert "standard|compact" in setup["run"]
    assert "compact cannot be combined with replay" in setup["run"]
    engine = _step(action, "Run Exhibit A")
    assert engine["env"]["IN_PROFILE"] == "${{ inputs.profile }}"
    assert '--profile "$IN_PROFILE"' in engine["run"]


def _verify_steps() -> dict[str, dict]:
    steps = _load_workflow()["jobs"]["verify"]["steps"]
    return {step.get("id", step.get("name")): step for step in steps}


def test_workflow_runs_only_for_the_demo_directory() -> None:
    workflow = _load_workflow()
    triggers = workflow.get("on", workflow.get(True, {}))
    assert triggers["pull_request"]["paths"] == ["examples/action-demo/**"]


def test_workflow_uses_compact_profile_and_a_small_budget() -> None:
    with_ = _verify_steps()["exhibit"]["with"]
    assert with_["profile"] == "compact"
    assert 0 < float(with_["budget-usd"]) <= 2
    assert with_["fail-on"] == "proven"


def test_workflow_analyses_the_scoped_repository_not_the_whole_checkout() -> None:
    steps = _verify_steps()
    with_ = steps["exhibit"]["with"]
    assert with_["working-directory"] == ".exhibit-a-scope"
    assert with_["base-sha"] == "${{ steps.scope.outputs.base }}"
    assert with_["head-sha"] == "${{ steps.scope.outputs.head }}"
    scope = steps["scope"]
    assert "examples/action-demo" in scope["run"]
    # PR-controlled values reach the script only through env, never through ${{ }} in it.
    assert "${{" not in scope["run"]
    assert scope["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    names = list(steps)
    assert names.index("scope") < names.index("exhibit")


def test_workflow_secret_is_referenced_by_name_only() -> None:
    text = WORKFLOW_YML.read_text(encoding="utf-8")
    assert "${{ secrets.EXHIBIT_A_API_KEY }}" in text
    assert _load_workflow()["jobs"]["verify"]["environment"] == "exhibit-a"

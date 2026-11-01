"""Node oracle red-team gate: every spec attack plus Node-specific extras.

Each attack runs twice through the real host-path oracle (``run_oracle`` with
``language="javascript"``): with the static tripwire on (the product
configuration) and off (what the in-oracle layers achieve on their own). Every
true exploit must be DETECTED, every cheat must be BLOCKED, except:

* R-JS1 / R-JS2 (strict xfails): the two false-proof families the red team got
  through (subverted shared builtins, obfuscated test-chosen root). If one of
  these starts passing, the limit was closed and docs/oracle/js-oracle.md plus
  this file must be updated.
* R-JS3 (asserted as-is): the subprocess-read recall probe. A recall limit
  produces no false proof, so it is asserted SUPPRESSED_TRUE, not xfailed.
* R-JS4 was the HTTP-dispatch recall residual. T136 HTTP-boundary attribution
  now detects a genuine ``request``-turn leak (``attack_js_read_http_handler_unattributed``)
  and still blocks a test-created server and a test listener on the app's server.

``spikes/redteam_js/run_all.py`` prints the same table for humans (run it with
``-v`` for the per-attack reasons); this file pins it as a gate. No Docker is
needed: the host path drives ``node --test`` directly, like
``tests/test_oracle_js.py`` (the docker-marked tests there cover the sandbox).
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spikes" / "redteam_js"))

import _harness  # noqa: E402
import run_all  # noqa: E402

BLOCKED = ("BLOCKED", "BLOCKED")
DETECTED = ("DETECTED", "DETECTED")
SUPPRESSED = ("SUPPRESSED_TRUE", "SUPPRESSED_TRUE")

# Desired (guard-on, guard-off) verdicts. Residuals want BLOCKED and currently
# prove, so they fail here and are pinned xfail below.
WANT = {
    "attack_js_read_direct_from_test": BLOCKED,
    "attack_js_read_vm_context": BLOCKED,
    "attack_js_read_require_cache_delete": BLOCKED,
    "attack_js_read_internal_binding": BLOCKED,
    "attack_js_read_forged_source_url": BLOCKED,
    "attack_js_read_prepare_stack_tamper": BLOCKED,
    "attack_js_read_module_create_require": BLOCKED,
    "attack_js_read_write_app_file": BLOCKED,
    "attack_js_read_modify_import_restore": BLOCKED,
    "attack_js_read_symlink_race": BLOCKED,
    "attack_js_read_obfuscated_allowed_root": BLOCKED,
    "attack_js_read_async_detached_promise": BLOCKED,
    "attack_js_read_worker_thread_escape": BLOCKED,
    "attack_js_read_key_introspection": BLOCKED,
    "attack_js_read_prototype_pollution": BLOCKED,
    "attack_js_exec_direct_spawn_from_test": BLOCKED,
    "attack_js_exec_marker_direct_write": BLOCKED,
    "attack_js_exec_process_env_path_injection": BLOCKED,
    "attack_js_exec_copied_canary": BLOCKED,
    "attack_js_exec_unrelated_process": BLOCKED,
    "attack_js_exec_at_exit_handler": BLOCKED,
    "attack_js_exec_r1_cell_tamper": BLOCKED,
    "attack_js_read_true_traversal": DETECTED,
    "attack_js_read_true_async_traversal": DETECTED,
    "attack_js_exec_true_command_injection": DETECTED,
    "attack_js_exec_true_spawn_injection": DETECTED,
    "attack_js_exec_deep_stack_true": DETECTED,
    "attack_js_read_require_cache_poison": BLOCKED,
    "attack_js_read_module_cache_direct": BLOCKED,
    "attack_js_read_loader_hijack": BLOCKED,
    "attack_js_read_getbuiltin_direct": BLOCKED,
    "attack_js_read_fd_slice": BLOCKED,
    "attack_js_read_symlink_backdate": BLOCKED,
    "attack_js_read_worker_file_entry": BLOCKED,
    "attack_js_read_vm_new_context_filename": BLOCKED,
    "attack_js_read_vm_this_context_filename": BLOCKED,
    "attack_js_read_vm_script_filename": BLOCKED,
    "attack_js_read_vm_compile_function": BLOCKED,
    "attack_js_read_stack_hook_frozen": BLOCKED,
    "attack_js_read_stack_hook_getter": BLOCKED,
    "attack_js_read_limit_zero": BLOCKED,
    "attack_js_read_limit_one": BLOCKED,
    "attack_js_read_limit_infinity": BLOCKED,
    "attack_js_read_limit_deleted": BLOCKED,
    "attack_js_read_capture_replaced": BLOCKED,
    "attack_js_read_http_handler_unattributed": DETECTED,
    "attack_js_read_http_test_server": BLOCKED,
    "attack_js_read_http_test_listener": BLOCKED,
    "attack_js_read_path_join_patch": BLOCKED,
    "attack_js_exec_env_define_property": BLOCKED,
    "attack_js_exec_node_options_strip": BLOCKED,
    "attack_js_exec_test_side_copy": BLOCKED,
    "attack_js_read_esm_import_direct": BLOCKED,
    "attack_js_read_subprocess_cat": SUPPRESSED,
    "attack_js_read_napi_addon_stub": BLOCKED,
}

RESIDUALS = {
    "attack_js_read_prototype_pollution": (
        "R-JS1 false proof (docs/oracle/js-oracle.md): patched String.prototype.includes "
        "lets ../ through the app's own check; genuine admitted frames, subverted heap."
    ),
    "attack_js_read_path_join_patch": (
        "R-JS1 false proof (docs/oracle/js-oracle.md): patched shared path.join redirects "
        "the app's own read to the canary; genuine admitted frames, subverted heap."
    ),
    "attack_js_read_obfuscated_allowed_root": (
        "R-JS2 false proof (docs/oracle/js-oracle.md): the app is rooted at the canary's "
        "directory through computed names and serves the canary's own path legitimately."
    ),
}

# Recall-class limits: observed (or missed) but unattributable, asserted as-is.
# A recall limit produces no false proof, so these are not xfails.
RECALL_WANT = {
    "attack_js_read_subprocess_cat": SUPPRESSED,
}

WANT.update(RECALL_WANT)
assert set(WANT) == set(run_all.ATTACKS), "table and runner disagree on the attack set"


def _params():
    for name in run_all.ATTACKS:
        if name in RESIDUALS:
            yield pytest.param(name, marks=pytest.mark.xfail(strict=True, reason=RESIDUALS[name]))
        else:
            yield pytest.param(name)


def _calls(name):
    """(guard-on record, guard-off record) from the harness forensic log."""
    recs = [c for c in _harness.CALLS if c["attack"] == name][-2:]
    assert len(recs) == 2 and recs[0]["guard"] is True and recs[1]["guard"] is False, (
        f"{name}: expected one guard-on and one guard-off run"
    )
    return recs[0], recs[1]


def _saw_effect(rec):
    assert rec["observed_effect"], f"{rec} should have produced an oracle event"


def _saw_no_effect(rec):
    assert not rec["observed_effect"], f"{rec} should have produced no oracle event"


@pytest.mark.parametrize("name", list(_params()))
def test_js_redteam_table(name):
    want_on, want_off = WANT[name]
    for guard in (True, False):
        _harness.GUARD = guard
        try:
            verdict = importlib.import_module(name).main()
        finally:
            _harness.GUARD = True
        want = want_on if guard else want_off
        assert verdict == want, f"{name} guard={'on' if guard else 'off'}: got {verdict}, want {want}"
    on, off = _calls(name)
    # The guard-on column may refuse via the tripwire; the guard-off column must
    # hold through the in-oracle layers, so it carries the honesty checks.
    if "DETECTED" in (want_on, want_off):
        assert off["test_outcome"] == "failed" and off["observed_effect"] and off["provenance_ok"]
    elif name == "attack_js_read_subprocess_cat":
        # R-JS3 recall: the external cat performs the read, the oracle sees nothing.
        assert off["test_outcome"] == "failed"
        _saw_no_effect(off)
    elif name in (
        "attack_js_read_limit_zero",
        "attack_js_read_limit_one",
        "attack_js_read_limit_infinity",
        "attack_js_read_limit_deleted",
        "attack_js_read_capture_replaced",
    ):
        # T136: limit games must neither forge a proof nor hide the test origin.
        # The preload captures with its own budget, so the test frame stays on
        # the stack and the direct read is refused for provenance.
        assert off["test_outcome"] == "failed"
        _saw_effect(off)
        assert off["reason_code"] == "provenance", off["reason"]
    elif name == "attack_js_read_http_test_server":
        # The leak fails the assertion, but only test frames are on the stack.
        assert off["test_outcome"] == "failed"
        _saw_effect(off)
    elif name == "attack_js_read_http_test_listener":
        # Extra listener on the app's server: the leak is test-originated even
        # if the request turn is stamped public-interface.
        assert off["test_outcome"] == "failed"
        _saw_effect(off)
    elif name in (
        "attack_js_read_internal_binding",
        "attack_js_read_key_introspection",
        "attack_js_exec_r1_cell_tamper",
        "attack_js_read_napi_addon_stub",
    ):
        # The hostile primitive fails before any effect: trap threw, key unreached,
        # cells unexposed, dlopen refused. The test passes with nothing observed.
        assert off["test_outcome"] == "passed"
        _saw_no_effect(off)
    elif name in ("attack_js_read_worker_thread_escape", "attack_js_read_worker_file_entry"):
        # The worker exfiltrates without hooks (no event), so the leak fails the
        # assertion but nothing is proven: fail-closed, no false proof.
        assert off["test_outcome"] == "failed"
        _saw_no_effect(off)
    elif name == "attack_js_read_stack_hook_frozen":
        # Frozen prepareStackTrace makes the capture refuse: an event with no
        # frames is recorded, but nothing is attributable. Fail closed.
        assert off["test_outcome"] == "failed"
        _saw_effect(off)
    elif name == "attack_js_read_write_app_file":
        assert off["tree_changes"], "planted helper must trip the app-tree check"
    elif name in ("attack_js_exec_unrelated_process",):
        assert off["test_outcome"] == "passed"
        _saw_no_effect(off)
    else:
        _saw_effect(off)

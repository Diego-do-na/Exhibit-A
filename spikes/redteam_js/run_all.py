"""Run every host-testable Node attack and print a classification table.

Each attack runs twice: as the product runs it (static tripwire on) and with the
tripwire off, which shows what the layers below it (signed events, frame
admission against the staged manifest, the app-tree tamper check, route checks,
provenance) achieve on their own; the tripwire is bypassable by obfuscation, so
the second column is the one that matters for forgery.

Results: FALSE_PROVEN / BLOCKED for a safe app, SUPPRESSED_TRUE / DETECTED for a
vulnerable one. Usage: ``python spikes/redteam_js/run_all.py`` from the repo root.
"""
import contextlib
import importlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import _harness  # noqa: E402

# Spec attacks 1-26 from docs/oracle/js-oracle.md, then Node-specific extras.
ATTACKS = [
    # --- canary_read cheats (safe app; BLOCKED unless a residual proves) ---
    "attack_js_read_direct_from_test",
    "attack_js_read_vm_context",
    "attack_js_read_require_cache_delete",
    "attack_js_read_internal_binding",
    "attack_js_read_forged_source_url",
    "attack_js_read_prepare_stack_tamper",
    "attack_js_read_module_create_require",
    "attack_js_read_write_app_file",
    "attack_js_read_modify_import_restore",
    "attack_js_read_symlink_race",
    "attack_js_read_obfuscated_allowed_root",
    "attack_js_read_async_detached_promise",
    "attack_js_read_worker_thread_escape",
    "attack_js_read_key_introspection",
    "attack_js_read_prototype_pollution",
    # --- canary_exec cheats (safe app; BLOCKED unless a residual proves) ---
    "attack_js_exec_direct_spawn_from_test",
    "attack_js_exec_marker_direct_write",
    "attack_js_exec_process_env_path_injection",
    "attack_js_exec_copied_canary",
    "attack_js_exec_unrelated_process",
    "attack_js_exec_at_exit_handler",
    "attack_js_exec_r1_cell_tamper",
    # --- controls (vulnerable app; DETECTED) ---
    "attack_js_read_true_traversal",
    "attack_js_read_true_async_traversal",
    "attack_js_exec_true_command_injection",
    "attack_js_exec_true_spawn_injection",
    "attack_js_exec_deep_stack_true",
    # --- Node-specific extras (safe app unless noted) ---
    "attack_js_read_require_cache_poison",
    "attack_js_read_module_cache_direct",
    "attack_js_read_loader_hijack",
    "attack_js_read_getbuiltin_direct",
    "attack_js_read_fd_slice",
    "attack_js_read_symlink_backdate",
    "attack_js_read_worker_file_entry",
    "attack_js_read_vm_new_context_filename",
    "attack_js_read_vm_this_context_filename",
    "attack_js_read_vm_script_filename",
    "attack_js_read_vm_compile_function",
    "attack_js_read_stack_hook_frozen",
    "attack_js_read_stack_hook_getter",
    "attack_js_read_limit_zero",
    "attack_js_read_limit_one",
    "attack_js_read_limit_infinity",
    "attack_js_read_limit_deleted",
    "attack_js_read_capture_replaced",
    "attack_js_read_http_handler_unattributed",
    "attack_js_read_http_test_server",
    "attack_js_read_http_test_listener",
    "attack_js_read_path_join_patch",
    "attack_js_exec_env_define_property",
    "attack_js_exec_node_options_strip",
    "attack_js_exec_test_side_copy",
    "attack_js_read_esm_import_direct",
    # --- recall-limit probes (vulnerable app; SUPPRESSED_TRUE documents R3) ---
    "attack_js_read_subprocess_cat",
    # --- native-addon stub (safe app; load fails closed) ---
    "attack_js_read_napi_addon_stub",
]

if __name__ == "__main__":
    verbose = "-v" in sys.argv
    rows = []
    for name in ATTACKS:
        mod = importlib.import_module(name)
        verdicts = []
        for guard in (True, False):
            _harness.GUARD = guard
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                verdicts.append(mod.main())
            if verbose:
                print(f"--- guard={'on' if guard else 'off'}\n{out.getvalue()}")
        rows.append((name, *verdicts))
    _harness.GUARD = True
    print("\n==== SUMMARY ====")
    print(f"  {'attack':38} {'guard on':16} guard off")
    for name, on, off in rows:
        print(f"  {name:38} {on:16} {off}")

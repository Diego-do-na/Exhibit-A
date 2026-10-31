"""Run every host-testable attack and print a classification table.

Each attack runs twice: as the product runs it (static tripwire on) and with the tripwire off,
which shows what the layers below it (signed events, frame admission against the staged
manifest, the app-tree tamper check, dir_fd resolution) achieve on their own; the tripwire
is bypassable by obfuscation, so the second column is the one that matters for forgery.

Results: FALSE_PROVEN / BLOCKED for a safe app, SUPPRESSED_TRUE / DETECTED for a vulnerable
one. Usage: ``python spikes/redteam/run_all.py`` from the repo root.
"""
import contextlib
import importlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import _harness  # noqa: E402

ATTACKS = [
    "attack_forged_frame_filename",
    "attack_forged_frame_same_line",
    "attack_write_app_module",
    "attack_modify_import_restore",
    "attack_differential_bypass",
    "attack_forge_events",
    "attack_key_introspection",
    "attack_dependency_monkeypatch",
    "attack_subprocess_sink",
    "attack_os_open_dir_fd",
    "attack_ctypes_libc_open",
    "attack_symlink_recheck",
    "attack_exec_canary_from_test",
    "attack_exec_test_thread",
    "attack_exec_marker_write",
    "attack_exec_outside_swap",
    "attack_exec_path_shim",
    "attack_exec_native_system",
    "attack_exec_raw_fork_exec",
    "attack_exec_at_exit",
    "attack_exec_finalizer",
    "attack_exec_stdlib_patch",
    "attack_exec_frameless_callable",
    "attack_exec_copied_canary",
    "attack_exec_true_injection",
    "attack_exec_true_pickle",
    "attack_exec_r1_cell_tamper",
    "attack_exec_r5_app_binding",
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

"""Run every host-testable attack and print a one-line classification each."""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

ATTACKS = [
    "attack_forged_frame_filename",
    "attack_write_app_module",
    "attack_forge_events",
    "attack_subprocess_sink",
    "attack_os_open_dir_fd",
    "attack_ctypes_libc_open",
    "attack_symlink_recheck",
]

if __name__ == "__main__":
    results = {}
    for name in ATTACKS:
        mod = importlib.import_module(name)
        results[name] = mod.main()
    print("\n==== SUMMARY ====")
    for name, verdict in results.items():
        print(f"  {verdict:16} {name}")

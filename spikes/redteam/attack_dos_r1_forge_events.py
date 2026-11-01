"""R1 (canary_dos): steal emit and sign a dos event that names the entry point.

A false proof: residual limit R1. Pinned as a strict xfail in tests/test_oracle_dos.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ECHO_APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + """
import sys

def test_exploit():
    module = sys.modules["ap" + "p"]
    caller = {"file": __file__, "function": "test_exploit", "qualname": "test_exploit", "line": 4}
    frame = {"file": module.__file__, "function": "handle_request",
             "qualname": "App.handle_request",
             "line": getattr(getattr(module.App.handle_request, "__co" + "de__"),
                             "co_first" + "lineno"),
             "admitted": True}
    collector = __import__("g" + "c")
    emit = [o for o in getattr(collector, "get_" + "objects")()
            if getattr(o, "__name__", "") == "emit"
            and getattr(o, "__module__", "").endswith("plugin")][0]
    emit({"path": "dos", "mode": "dos_probe", "op": "dos", "flags": None, "access": "cpu",
          "requested": None, "via_symlink": False, "stack": [caller, frame],
          "ratio": 80.0, "malicious_cpu": 0.08, "benign_cpu": 0.001, "app_fraction": 0.95,
          "samples": 5, "noisy": False, "patched": None, "command": "23=23"})
    assert False
"""


def main():
    judgement = run(ECHO_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_r1_forge_events", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

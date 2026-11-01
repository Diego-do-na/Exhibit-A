"""Residual R1 (canary_access): a test that steals the signing key forges a matching response (pinned)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import ENTRY, FIXED_APP as APP, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    import sys
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
    emit({"path": "da" + "ta/store.js" + "on", "mode": "response_probe", "op": "response",
          "flags": None, "access": None, "requested": None, "via_symlink": False,
          "stack": [caller, frame], "status": 200, "location": None, "body": TOKEN,
          "auth": ATTACKER, "resource": RESOURCE, "patched": None})
    assert False
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_access")
    return report('attack_access_r1_forge_events', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

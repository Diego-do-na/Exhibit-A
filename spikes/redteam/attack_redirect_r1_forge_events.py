"""Residual R1 (canary_redirect): a test that steals the signing key forges a matching response (pinned)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
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
    emit({"path": URL, "mode": "response_probe", "op": "response", "flags": None,
          "access": None, "requested": None, "via_symlink": False,
          "stack": [caller, frame], "status": 302, "location": URL, "body": "Found",
          "auth": None, "resource": None, "patched": None})
    assert False
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_redirect")
    return report('attack_redirect_r1_forge_events', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

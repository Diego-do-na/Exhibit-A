"""Attack (canary_sql, R1): find the plugin's signer and sign the connection and the read an app would produce.

R1 again (docs/oracle/oracle-provenance.md 7.1), through the new effect: the signing key lives in the test's
own process. With computed names the test slips past the tripwire, finds ``emit`` and signs a
``sql_connect`` and a ``sql_read`` whose stack names the test and the entry point's real frame. The
host re-check passes because those are real. A declared residual limit, pinned by a strict xfail.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import PARAM_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import sys

def test_exploit():
    module = sys.modules["ap" + "p"]
    handler = getattr(module.App.handle_request, "__co" + "de__")
    frame = {"file": module.__file__, "function": "handle_request", "qualname": "App.handle_request",
             "line": getattr(handler, "co_first" + "lineno"), "admitted": True}
    caller = {"file": __file__, "function": "test_exploit", "qualname": "test_exploit", "line": 1}
    collector = __import__("g" + "c")
    emit = [o for o in getattr(collector, "get_" + "objects")()
            if getattr(o, "__name__", "") == "emit" and getattr(o, "__module__", "").endswith("plugin")][0]
    base = {"path": module.DB, "flags": None, "access": "sql", "requested": None, "target": "db",
            "via_symlink": False, "symlink": None, "stack": [caller, frame], "connection": 77}
    emit({**base, "mode": "sql" + "ite3.connect/handle", "op": "sql_connect", "declared_db": True,
          "command": module.DB, "instrumented": True, "patched": None})
    emit({**base, "mode": "sql_read", "op": "sql_read", "declared_db": True, "table": "exhibit_canary",
          "column": "token", "database": "main"})
    assert False
"""


def main():
    return report("sql_r1_forge_events", cheat(EXPLOIT, PARAM_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

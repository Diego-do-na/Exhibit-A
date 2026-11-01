"""R1 (canary_connect): the test steals the plugin key and signs its own events.

With computed names the test finds the audit hook's emit cell in its own process and
signs a connection and a request that name the entry point's real frame. On the host
path this still proves nothing: the listener's log path is unknown to the test, so no
recorded request matches. In the sandbox the log path is fixed (/oracle/connect.jsonl),
so the same theft plus one forged line is a false proof (pinned by a strict xfail in
tests/test_oracle_connect.py instead of here).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
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
    host, _, rest = URL.split("/")[2].partition(":")
    port = int(rest.split("/")[0])
    base = {"path": URL, "flags": None, "access": "unknown", "requested": None,
            "via_symlink": False, "stack": [caller, frame], "host": host, "port": port, "url": None}
    emit({**base, "mode": "socket.connect", "op": "connect"})
    emit({**base, "mode": "urllib.Request", "op": "request", "url": URL})
    assert False
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_r1_forge_events', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (KNOWN, declared limit A-1): the test forges the events file directly.

The events file is passed to the test process by path (EXHIBIT_A_EVENTS) and is writable by
it (in the sandbox it is mounted ``:rw``). A hostile test writes a fully-formed event with an
application stack through the entry point and then ``assert False``. Confirmed still open; it
is included only to verify the declared limit reproduces unchanged, not as a new finding.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402

SAFE_APP = "    x = 1\n"

EXPLOIT = '''
    import json
    import os

    def test_forge():
        canary = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
        events = os.environ["EXHIBIT_A_EVENTS"]
        app_file = __import__("app").__file__
        record = {
            "type": "canary_read", "path": canary, "mode": "r", "via_symlink": False,
            "stack": [
                {"file": __file__, "function": "test_forge", "qualname": "test_forge"},
                {"file": app_file, "function": "handle_request", "qualname": "App.handle_request"},
            ],
        }
        with open(events, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\\n")
        assert False, "forged"
'''


def main():
    # The forged stack names the test file by a literal path; align test_dir by using the
    # harness layout where the test lives under .../tests/. We fake the frame file to that dir.
    return report("forge_events", run(SAFE_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=True)


if __name__ == "__main__":
    main()

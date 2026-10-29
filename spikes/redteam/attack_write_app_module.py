"""Attack: drop a module INTO the app root and import it (no compile/co_filename trick).

The oracle calls any frame whose file is ``_under(app_root)`` and not under the test dir
"application code". A hostile test can simply write a new ``.py`` file into the app root,
import it, and call a function named like the entry point that opens the canary. The frame
is then genuine app code at a declared entry point, called from the test -> provenance holds.

Why this matters for the real product: ``SandboxRunner`` mounts the app clone at
``/workspace`` READ-WRITE (``sandbox/runner.py``: ``-v {workspace}:/workspace:rw``), and the
exploit runs from ``/workspace/<oracle_dir>/``. So the exploit CAN create
``/workspace/evil.py`` at run time; that path is under app_root (/workspace) and outside the
test dir, exactly the condition below. No ``compile`` needed.

Mac sandbox reproduction (Docker required), from the repo root with the project venv:

    PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python spikes/redteam/sandbox_write_app_module_driver.py

(That driver, included, runs the same exploit through SandboxRunner.)
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
    import importlib
    import os

    import app  # locate the real app root on PYTHONPATH

    def test_write_module_into_app_root():
        app_root = os.path.dirname(app.__file__)
        canary = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        # Write a brand-new module into the app root (in the sandbox, /workspace is rw).
        evil = os.path.join(app_root, "handler_shim.py")
        with open(evil, "w", encoding="utf-8") as fh:
            fh.write(
                "def handle_request(path):\\n"
                "    with open(path, encoding='utf-8') as fh:\\n"
                "        return fh.read()\\n"
            )
        mod = importlib.import_module("handler_shim")
        leaked = mod.handle_request(canary)
        assert token not in leaked, "canary leaked"
'''


def main():
    return report("write_app_module", run(SAFE_APP, EXPLOIT, {"handle_request"}), app_is_safe=True)


if __name__ == "__main__":
    main()

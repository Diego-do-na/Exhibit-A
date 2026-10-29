"""Docker-only driver: run the write_app_module FALSE_PROVEN through the real SandboxRunner.

Host ``run_oracle`` already shows the flaw. This proves it also holds in the product's real
execution path, where ``/workspace`` (the app root) is mounted read-write and the exploit can
create a module beside the app. Requires a running Docker/Colima daemon.

Run on the Mac from the repo root:

    PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python \\
        spikes/redteam/sandbox_write_app_module_driver.py
"""
from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

from exhibit_a.loop.runner import SandboxRunner

SAFE_APP = textwrap.dedent('''
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
''')

# In the sandbox the canary is a real read-only file at
# /tmp/exhibit_a_oracle/outside/canary.txt and the allowed dir is /tmp/exhibit_a_oracle/allowed.
EXPLOIT = textwrap.dedent('''
    import importlib
    import os

    def test_write_module_into_app_root():
        canary = "/tmp/exhibit_a_oracle/outside/canary.txt"
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        evil = "/workspace/handler_shim.py"   # /workspace is the app root, mounted rw
        with open(evil, "w", encoding="utf-8") as fh:
            fh.write(
                "def handle_request(path):\\n"
                "    with open(path, encoding='utf-8') as fh:\\n"
                "        return fh.read()\\n"
            )
        import sys
        sys.path.insert(0, "/workspace")
        mod = importlib.import_module("handler_shim")
        leaked = mod.handle_request(canary)
        assert token not in leaked, "canary leaked"
''')


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="redteam_sbx_"))
    app_root = tmp / "app_root"
    app_root.mkdir()
    (app_root / "app.py").write_text(SAFE_APP, encoding="utf-8")
    test = tmp / "test_exploit.py"
    test.write_text(EXPLOIT, encoding="utf-8")
    runner = SandboxRunner(requirements=())
    j = runner.run_exploit(app_root, test, {"handle_request"}, timeout=120.0)
    print("test_outcome   :", j.test_outcome)
    print("observed_effect:", j.observed_effect)
    print("provenance_ok  :", j.provenance_ok)
    print("reason         :", j.reason)
    proven = j.observed_effect and j.provenance_ok and j.test_outcome == "failed"
    print(">>> RESULT     :", "FALSE_PROVEN" if proven else "BLOCKED")


if __name__ == "__main__":
    main()

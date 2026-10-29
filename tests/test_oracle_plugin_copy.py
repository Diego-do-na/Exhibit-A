"""Audit F20: the host oracle run loads a private read-only copy of the plugin."""

import json
import shutil
from pathlib import Path

from exhibit_a.oracle import run_oracle

ROOT = Path(__file__).resolve().parent.parent
APP = Path(__file__).parent / "fixtures" / "oracle_eval" / "vulnerable"

PROBE = '''
import json, os, sys

def test_probe():
    # The guard rejects tests that name the plugin module, so find it by suffix.
    (plugin,) = [m for n, m in list(sys.modules.items()) if n.endswith("oracle_plugin")]
    path = plugin.__file__
    report = {
        "plugin": path,
        "writable": os.access(path, os.W_OK),
        "dir_writable": os.access(os.path.dirname(path), os.W_OK),
    }
    with open(%r, "w") as fh:
        json.dump(report, fh)
'''


def test_plugin_is_a_private_read_only_copy(tmp_path):
    app = tmp_path / "app"
    shutil.copytree(APP, app)
    out = tmp_path / "report.json"
    test = tmp_path / "test_probe.py"
    test.write_text(PROBE % str(out))

    run_oracle(app, test, {"App.handle_request"})

    report = json.loads(out.read_text())
    plugin = Path(report["plugin"]).resolve()
    assert plugin != (ROOT / "src" / "exhibit_a" / "oracle" / "plugin.py").resolve()
    assert not plugin.is_relative_to(ROOT)
    assert report["writable"] is False and report["dir_writable"] is False

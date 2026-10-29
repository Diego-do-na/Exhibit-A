"""Attack (recall): a genuinely vulnerable app whose sink reads via a subprocess.

The plugin only audits the ``open`` event IN THE TEST PROCESS. An app that reads the file by
shelling out (``cat``) leaks the canary just as badly, but the read happens in a child
process with no audit hook, so no ``canary_read`` event is ever written. The oracle then
concludes "test failed but the canary was never read: wrong reason" and SUPPRESSES a true
proof. Path traversal into a program that execs a reader is entirely realistic.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402

VULN_APP = '''
    import os
    import subprocess
    class App:
        def __init__(self, base_dir):
            self.base_dir = base_dir
        def handle_request(self, name):
            # VULNERABLE: no confinement, and reads via an external process.
            path = os.path.join(self.base_dir, name)
            return subprocess.run(["cat", path], capture_output=True, text=True).stdout
'''

EXPLOIT = '''
    import os
    from app import App
    def test_traversal():
        app = App(os.environ["EXHIBIT_A_ALLOWED_DIR"])
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        leaked = app.handle_request("../outside/canary.txt")
        assert token not in leaked, "canary leaked via subprocess"
'''


def main():
    return report("subprocess_sink", run(VULN_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=False)


if __name__ == "__main__":
    main()

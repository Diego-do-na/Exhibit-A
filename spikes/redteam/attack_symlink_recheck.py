"""Re-check (expected BLOCKED): the A-2 planted-symlink cheat, to confirm it is now caught.

A-2's fix flags canary opens whose requested path goes through a symlink created during the
run. This plants such a link in the allowed dir and reads through it; the oracle must reject
it (``via_symlink``). Included to confirm the existing defense still holds.
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
            # Lexically safe: rejects ".." but follows symlinks inside base_dir.
            if ".." in name.split("/"):
                raise PermissionError("no traversal")
            with open(os.path.join(self.base_dir, name), encoding="utf-8") as fh:
                return fh.read()
'''

EXPLOIT = '''
    import os
    from app import App
    def test_symlink():
        allowed = os.environ["EXHIBIT_A_ALLOWED_DIR"]
        canary = os.path.join(os.path.dirname(allowed), "outside", "canary.txt")
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        link = os.path.join(allowed, "leak.txt")
        os.symlink(canary, link)  # planted during the run
        app = App(allowed)
        leaked = app.handle_request("leak.txt")
        assert token not in leaked, "canary leaked via planted symlink"
'''


def main():
    return report("symlink_recheck", run(SAFE_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=True)


if __name__ == "__main__":
    main()

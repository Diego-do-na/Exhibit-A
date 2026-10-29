"""Attack (recall): a vulnerable app that reads with os.open + dir_fd (openat).

The audit ``open`` event carries the RELATIVE path when ``dir_fd`` is used; the plugin does
``os.path.realpath(requested)`` which resolves against the current working directory, not the
directory fd. So a real traversal performed relative to an attacker-influenced directory fd
resolves to a different path, never equals the canary, and no event is written: a true read
is suppressed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402

VULN_APP = '''
    import os
    class App:
        def __init__(self, base_dir):
            self.base_dir = base_dir
        def handle_request(self, name):
            # VULNERABLE: opens name relative to a dir fd for the sibling "outside" dir.
            outside = os.path.join(os.path.dirname(self.base_dir), "outside")
            dfd = os.open(outside, os.O_RDONLY)
            try:
                fd = os.open(name, os.O_RDONLY, dir_fd=dfd)  # name="canary.txt"
                try:
                    return os.read(fd, 1 << 20).decode()
                finally:
                    os.close(fd)
            finally:
                os.close(dfd)
'''

EXPLOIT = '''
    import os
    from app import App
    def test_traversal():
        app = App(os.environ["EXHIBIT_A_ALLOWED_DIR"])
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        leaked = app.handle_request("canary.txt")
        assert token not in leaked, "canary leaked via openat"
'''


def main():
    return report("os_open_dir_fd", run(VULN_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=False)


if __name__ == "__main__":
    main()

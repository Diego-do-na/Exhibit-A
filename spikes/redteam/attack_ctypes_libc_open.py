"""Attack (recall): a vulnerable app that reads the file via libc open through ctypes.

``ctypes`` calls into ``open(2)`` directly, bypassing CPython's ``open`` audit event entirely.
The canary is leaked but the plugin never sees it, so a true proof is suppressed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402

VULN_APP = '''
    import ctypes
    import os
    _libc = ctypes.CDLL(None, use_errno=True)
    class App:
        def __init__(self, base_dir):
            self.base_dir = base_dir
        def handle_request(self, name):
            path = os.path.join(self.base_dir, name)  # VULNERABLE: no confinement
            fd = _libc.open(path.encode(), os.O_RDONLY)
            if fd < 0:
                raise OSError(ctypes.get_errno(), "open failed")
            try:
                buf = os.read(fd, 1 << 20)
            finally:
                _libc.close(fd)
            return buf.decode()
'''

EXPLOIT = '''
    import os
    from app import App
    def test_traversal():
        app = App(os.environ["EXHIBIT_A_ALLOWED_DIR"])
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        leaked = app.handle_request("../outside/canary.txt")
        assert token not in leaked, "canary leaked via libc open"
'''


def main():
    return report("ctypes_libc_open", run(VULN_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=False)


if __name__ == "__main__":
    main()

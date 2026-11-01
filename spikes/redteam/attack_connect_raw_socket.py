"""Attack (canary_connect): the test speaks HTTP over a raw socket itself."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import socket
    import urllib.parse
    parts = urllib.parse.urlsplit(URL)
    sock = socket.create_connection((parts.hostname, parts.port), timeout=5)
    sock.sendall(("GET " + parts.path + " HTTP/1.0\r\n\r\n").encode())
    body = sock.recv(4096).decode()
    sock.close()
    assert False, body[:10]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_raw_socket', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

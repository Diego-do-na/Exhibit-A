"""Attack (canary_connect): the test connects to the canary itself; a test frame refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import socket
    host, _, rest = URL.split("/")[2].partition(":")
    port = int(rest.split("/")[0]) if rest else 80
    sock = socket.create_connection((host, port), timeout=5)
    sock.close()
    assert False
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_from_test', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

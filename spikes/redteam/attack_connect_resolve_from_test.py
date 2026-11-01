"""Attack (canary_connect): the test resolves the canary host itself."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import socket
    host = URL.split("/")[2].split(":")[0]
    socket.getaddrinfo(host, 80)
    assert False
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_resolve_from_test', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_connect): the test requests the URL itself with urllib."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import urllib.request
    with urllib.request.urlopen(URL, timeout=5) as resp:
        body = resp.read().decode()
    assert False, body[:10]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_request_from_test', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

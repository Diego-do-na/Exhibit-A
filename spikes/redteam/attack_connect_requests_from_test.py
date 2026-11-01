"""Attack (canary_connect): the test requests the URL itself with requests."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import requests
    body = requests.get(URL, timeout=5).text
    assert False, body[:10]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_requests_from_test', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_connect): the test reads the listener log; no app request, no proof."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    data = open("/oracle/connect.jsonl", encoding="utf-8").read()
    assert False, data[:10]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_read_log', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

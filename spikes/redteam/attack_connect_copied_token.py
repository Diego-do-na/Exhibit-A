"""Attack (canary_connect): the test feeds the token to an echo app; no request happens."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ECHO_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    assert TOKEN not in str(App().handle_request(TOKEN))
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_copied_token', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

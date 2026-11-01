"""True localhost spelling (canary_connect): 127.0.0.1 and localhost are the same service."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import DIRECT_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    try:
        body = App().handle_request(URL.replace("127.0.0.1", "localhost"))
    except Exception:
        return
    assert TOKEN not in body
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_true_localhost', judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

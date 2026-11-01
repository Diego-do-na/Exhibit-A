"""Attack (canary_dos): the test times the call itself; the runner never measured."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ECHO_APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + """
import time

def test_exploit():
    t = time.process_time()
    App().handle_request("x")
    assert time.process_time() - t < 0.001
"""


def main():
    judgement = run(ECHO_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_times_itself", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

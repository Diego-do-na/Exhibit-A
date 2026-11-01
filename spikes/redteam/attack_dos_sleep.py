"""Attack (canary_dos): the test sleeps, then fails; CPU was not spent in the app."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ECHO_APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + """
import time

def test_exploit():
    time.sleep(0.2)
    assert False
"""


def main():
    judgement = run(ECHO_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_sleep", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

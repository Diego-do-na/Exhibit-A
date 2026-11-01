"""Attack (canary_dos): the test fails without going through dos_probe; no timing event."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ENTRY, PRELUDE, REDOS_APP  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + """
def test_exploit():
    assert False
"""


def main():
    judgement = run(REDOS_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_no_probe", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

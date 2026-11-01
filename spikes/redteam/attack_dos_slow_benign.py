"""Attack (canary_dos): swapping malicious and benign so the 'benign' input is the slow one."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ENTRY, REDOS_APP, REDOS_BEN, REDOS_MAL, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + f"""
def test_exploit(dos_probe):
    dos_probe(App().handle_request, malicious={REDOS_BEN!r}, benign={REDOS_MAL!r})
"""


def main():
    judgement = run(REDOS_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_slow_benign", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

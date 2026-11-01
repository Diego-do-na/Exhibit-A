"""Control (canary_dos): catastrophic backtracking through the entry point is DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ENTRY, REDOS_APP, REDOS_EXPLOIT  # noqa: E402
from _harness import report, run  # noqa: E402


def main():
    judgement = run(REDOS_APP, REDOS_EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_true_redos", judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

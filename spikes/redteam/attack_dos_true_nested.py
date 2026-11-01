"""Control (canary_dos): nested quantifiers through the entry point is DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ENTRY, NESTED_APP, NESTED_EXPLOIT  # noqa: E402
from _harness import report, run  # noqa: E402


def main():
    judgement = run(NESTED_APP, NESTED_EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_true_nested", judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

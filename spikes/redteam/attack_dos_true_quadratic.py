"""Control (canary_dos): quadratic string building through the entry point is DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ENTRY, QUAD_APP, QUAD_EXPLOIT  # noqa: E402
from _harness import report, run  # noqa: E402


def main():
    judgement = run(QUAD_APP, QUAD_EXPLOIT, ENTRY, effect="canary_dos", timeout=60.0)
    return report("attack_dos_true_quadratic", judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

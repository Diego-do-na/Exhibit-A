"""Attack (canary_dos): the probe calls an internal helper, not the declared entry point."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ENTRY, HELPER_APP, PRELUDE, REDOS_BEN, REDOS_MAL  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + f"""
import app

def test_exploit(dos_probe):
    dos_probe(app.scan, malicious={REDOS_MAL!r}, benign={REDOS_BEN!r})
"""


def main():
    judgement = run(HELPER_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_helper", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

"""R5 (canary_dos): replace a binding in the app so admitted code runs a catastrophic pattern.

A false proof: residual limit R5. Pinned as a strict xfail in tests/test_oracle_dos.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ENTRY, PRELUDE, R5_APP  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + """
import sys

def test_exploit(dos_probe):
    setattr(sys.modules["ap" + "p"], "PAT" + "TERN", r"(a+)+$")
    dos_probe(App().handle_request, malicious="a" * 22 + "!", benign="b" * 23)
"""


def main():
    judgement = run(R5_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_r5_app_binding", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

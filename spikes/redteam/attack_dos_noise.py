"""Attack (canary_dos): random extra work around a safe app must not mint a proof."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ECHO_APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + """
import random

def test_exploit(dos_probe):
    def noisy(data):
        n = random.randint(0, 400000)
        acc = 0
        for i in range(n):
            acc += i
        return App().handle_request(data)
    dos_probe(noisy, malicious="a" * 23, benign="b" * 23)
"""


def main():
    judgement = run(ECHO_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_noise", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_dos): a test-frame busy loop around a safe app is not application CPU."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _dos_cases import ECHO_APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = PRELUDE + """
def test_exploit(dos_probe):
    def slow(data):
        n = 0
        for i in range(2_000_000):
            n += i
        return App().handle_request(data)
    dos_probe(slow, malicious="a" * 23, benign="b" * 23)
"""


def main():
    judgement = run(ECHO_APP, EXPLOIT, ENTRY, effect="canary_dos")
    return report("attack_dos_busy_loop", judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

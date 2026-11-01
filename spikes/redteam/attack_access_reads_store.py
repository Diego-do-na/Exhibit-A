"""Attack (canary_access): the test reads the seeded store directly; refused."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import VULN_APP as APP, cheat  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    with open("data/store.json", encoding="utf-8") as fh:
        body = fh.read()
    assert False, body[:50]
"""


def main():
    from _harness import report
    return report('attack_access_reads_store', cheat(EXPLOIT, app=APP), app_is_safe=True)


if __name__ == "__main__":
    main()

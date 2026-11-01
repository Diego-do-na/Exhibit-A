"""Attack (canary_access): the test builds the response itself; a test frame refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import VULN_APP as APP, cheat  # noqa: E402


EXPLOIT = """
def fake(auth, resource):
    return TOKEN

def test_exploit(access_probe):
    resp = access_probe(fake, ATTACKER, RESOURCE)
    assert False, resp
"""


def main():
    from _harness import report
    return report('attack_access_builds_response', cheat(EXPLOIT, app=APP), app_is_safe=True)


if __name__ == "__main__":
    main()

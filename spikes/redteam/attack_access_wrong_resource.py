"""Attack (canary_access): the test asks for a resource outside the contract; no match refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import VULN_APP as APP, cheat  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    try:
        resp = access_probe(App().handle_request, ATTACKER, "other-doc")
    except Exception:
        return
    assert TOKEN not in resp["body"], resp["body"][:50]
"""


def main():
    from _harness import report
    return report('attack_access_wrong_resource', cheat(EXPLOIT, app=APP), app_is_safe=True)


if __name__ == "__main__":
    main()

"""True IDOR (canary_access): the app returns the resource unchecked; the control proves."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import ENTRY, PRELUDE, VULN_APP as APP  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    try:
        resp = access_probe(App().handle_request, ATTACKER, RESOURCE)
    except Exception:
        return
    assert TOKEN not in resp["body"], resp["body"][:50]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_access")
    return report('attack_access_true_unchecked', judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

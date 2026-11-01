"""Attack (canary_access): the test probes the app's internal lookup; provenance refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import HELPER_APP as APP, cheat  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    import app
    try:
        resp = access_probe(app.lookup, ATTACKER, RESOURCE)
    except Exception:
        return
    assert TOKEN not in resp["body"], resp["body"][:50]
"""


def main():
    from _harness import report
    return report('attack_access_internal_helper', cheat(EXPLOIT, app=APP), app_is_safe=True)


if __name__ == "__main__":
    main()

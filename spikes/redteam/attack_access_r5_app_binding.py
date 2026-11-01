"""Residual R5 (canary_access): the test disables the app's ownership check by computed names (pinned)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import CHECK_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    import sys
    setattr(sys.modules["ap" + "p"], "CHE" + "CK", False)
    try:
        resp = access_probe(App().handle_request, ATTACKER, RESOURCE)
    except Exception:
        return
    assert TOKEN not in resp["body"], resp["body"][:50]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_access")
    return report('attack_access_r5_app_binding', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

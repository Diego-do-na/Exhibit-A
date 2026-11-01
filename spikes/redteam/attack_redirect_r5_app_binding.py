"""Residual R5 (canary_redirect): the test replaces the app's allow-list binding by computed names (pinned)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import ENTRY, PRELUDE, R5_APP as APP  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    import sys
    setattr(sys.modules["ap" + "p"], "ALLO" + "WED", URL.split("/")[2])
    try:
        resp = redirect_probe(App().handle_request, URL)
    except Exception:
        return
    assert resp["location"] != URL, resp
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_redirect")
    return report('attack_redirect_r5_app_binding', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

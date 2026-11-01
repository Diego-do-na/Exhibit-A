"""Attack (canary_redirect): the test probes the app's internal helper; provenance refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import HELPER_APP, cheat  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    import app
    try:
        resp = redirect_probe(app.redirect_to, URL)
    except Exception:
        return
    assert resp["location"] != URL, resp
"""


def main():
    from _harness import report
    return report('attack_redirect_internal_helper', cheat(EXPLOIT, app=HELPER_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

"""True redirect (canary_redirect): the app redirects to the caller URL; the control proves."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import DIRECT_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    try:
        resp = redirect_probe(App().handle_request, URL)
    except Exception:
        return
    assert resp["location"] != URL, resp
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_redirect")
    return report('attack_redirect_true_direct', judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

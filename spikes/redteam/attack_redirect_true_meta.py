"""True redirect (canary_redirect): the app answers with a meta refresh the case declares; the control proves."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import ENTRY, META_APP as APP, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    try:
        resp = redirect_probe(App().handle_request, URL)
    except Exception:
        return
    assert URL not in resp["body"], resp["body"][:100]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_redirect", redirect_meta=True)
    return report('attack_redirect_true_meta', judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

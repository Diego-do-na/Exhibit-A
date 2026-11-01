"""True redirect (canary_redirect): the app builds the redirect from the caller host; the control proves."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import ENTRY, HOST_APP as APP, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    import urllib.parse
    parts = urllib.parse.urlsplit(URL)
    try:
        resp = redirect_probe(App().handle_request, parts.netloc, parts.path.lstrip("/"))
    except Exception:
        return
    got = urllib.parse.urlsplit(resp["location"] or "").hostname or ""
    assert got != parts.hostname, resp
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_redirect")
    return report('attack_redirect_true_host', judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

"""Attack (canary_redirect): a meta refresh the case never declared; no match refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import META_APP, cheat  # noqa: E402


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
    return report('attack_redirect_meta_undeclared', cheat(EXPLOIT, app=META_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

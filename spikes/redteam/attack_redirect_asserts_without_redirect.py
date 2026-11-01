"""Attack (canary_redirect): the test fails without any redirect; no match refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import cheat  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    try:
        redirect_probe(App().handle_request, "https://shop.example.com/home")
    except Exception:
        pass
    assert False, "the test fails for the wrong reason"
"""


def main():
    from _harness import report
    return report('attack_redirect_asserts_without_redirect', cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

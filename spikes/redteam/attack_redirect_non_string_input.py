"""Attack (canary_redirect): the probe only passes strings; a hostile input fails closed."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import cheat  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    try:
        redirect_probe(App().handle_request, ["http://x/"])
    except TypeError:
        pass
    assert False, "the test fails for the wrong reason"
"""


def main():
    from _harness import report
    return report('attack_redirect_non_string_input', cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

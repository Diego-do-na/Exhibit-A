"""Attack (canary_redirect): the test builds the redirect response itself; a test frame refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import cheat  # noqa: E402


EXPLOIT = """
def fake(target):
    return (302, {"Location": target}, "Found")

def test_exploit(redirect_probe):
    resp = redirect_probe(fake, URL)
    assert False, resp
"""


def main():
    from _harness import report
    return report('attack_redirect_builds_response', cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_exec): shlex.quote replaced by computed names turns the safe app's own command into an injection."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    setattr(__import__("shl" + "ex"), "quo" + "te", str)
    App(ALLOWED).handle_request("x; " + CANARY)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_stdlib_patch", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

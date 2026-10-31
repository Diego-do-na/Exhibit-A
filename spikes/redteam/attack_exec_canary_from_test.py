"""Attack (canary_exec): The test runs the canary itself, under computed names the guard cannot read."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    getattr(__import__("o" + "s"), "sys" + "tem")(CANARY)
    App(ALLOWED).handle_request(CANARY)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_canary_from_test", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

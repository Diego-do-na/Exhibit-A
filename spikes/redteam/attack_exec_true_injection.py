"""Control (canary_exec): a real shell injection through the entry point must be DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import SHELL_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    App(ALLOWED).handle_request("x; " + CANARY)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_true_injection", cheat(EXPLOIT, SHELL_APP), app_is_safe=False)


if __name__ == "__main__":
    main()

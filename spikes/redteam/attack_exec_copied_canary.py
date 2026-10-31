"""Attack (canary_exec): A copy of the canary run through a real injection is not the canary: its name is elsewhere."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import shutil
def test_exploit():
    copy = os.path.join(ALLOWED, "canary")
    shutil.copy(CANARY, copy)
    App(ALLOWED).handle_request("x; " + copy)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_copied_canary", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

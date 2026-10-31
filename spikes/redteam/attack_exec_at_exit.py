"""Attack (canary_exec): A C callable registered with atexit runs after every test frame is gone."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import atexit
def test_exploit():
    atexit.register(getattr(os, "sys" + "tem"), CANARY)
    App(ALLOWED).handle_request(CANARY)
    assert False
"""


def main():
    return report("exec_at_exit", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_exec): system(3) through ctypes raises no process audit event, only ctypes ones."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    getattr(__import__("c" + "types"), "CDLL")(None).system(CANARY.encode())
    App(ALLOWED).handle_request(CANARY)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_native_system", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_exec): The canary runs from a thread the test started, while the app call looks clean."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import threading
def test_exploit():
    t = threading.Thread(target=getattr(os, "sys" + "tem"), args=(CANARY,))
    t.start()
    t.join()
    App(ALLOWED).handle_request(CANARY)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_test_thread", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

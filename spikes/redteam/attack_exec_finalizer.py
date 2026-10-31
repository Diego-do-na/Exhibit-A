"""Attack (canary_exec): A finalizer on cyclic garbage fires on whatever stack the collector interrupts, maybe the app's."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import gc
import weakref
class Garbage:
    pass
def test_exploit():
    g = Garbage()
    g.me = g
    weakref.finalize(g, getattr(os, "sys" + "tem"), CANARY)
    del g
    gc.set_threshold(1)
    App(ALLOWED).handle_request(CANARY)
    assert False
"""


def main():
    return report("exec_finalizer", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

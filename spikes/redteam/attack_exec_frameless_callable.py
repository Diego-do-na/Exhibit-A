"""Attack (canary_exec): A partial has no Python frame, so a safe app calling a method of its input looks like the starter."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

STREAM_APP = """
class App:
    def __init__(self, base):
        self.base = base
    def handle_request(self, stream):
        return stream.read()
"""

EXPLOIT = """
import functools
class Stream:
    pass
def test_exploit():
    stream = Stream()
    stream.read = functools.partial(getattr(os, "sys" + "tem"), CANARY)
    App(ALLOWED).handle_request(stream)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_frameless_callable", cheat(EXPLOIT, STREAM_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

"""Control (canary_exec): a real pickle.loads RCE through the entry point must be DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

APP = """
import pickle

class App:
    def __init__(self, base):
        self.base = base
    def handle_request(self, blob):
        return pickle.loads(blob)
"""

EXPLOIT = """
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, (CANARY,))
def test_exploit():
    App(ALLOWED).handle_request(pickle.dumps(Payload()))
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_true_pickle", cheat(EXPLOIT, APP), app_is_safe=False)


if __name__ == "__main__":
    main()

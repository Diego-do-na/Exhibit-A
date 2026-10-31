"""Attack (canary_exec): _posixsubprocess.fork_exec raises no audit event by itself; the plugin wraps it."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    raw = __import__("_posix" + "subprocess")
    try:
        getattr(raw, "fork_exec")([CANARY.encode()], [CANARY.encode()], True, (), None, None, -1, -1, -1, -1, -1, -1,
                                  *os.pipe(), False, False, 0, None, None, None, -1, None, False)
    except TypeError:
        pass  # the argument list changes between Python versions; the audit event comes first
    App(ALLOWED).handle_request(CANARY)
    assert False
"""


def main():
    return report("exec_raw_fork_exec", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_exec, R5): replace the app's own binding of its sanitiser by computed names.

R5 again (docs/oracle/oracle-provenance.md 7.5), through the new effect: the app's unmodified, admitted
code really builds the injected command. The install-time snapshot covers the stdlib's own
``shlex.quote`` (attack_exec_stdlib_patch), not a name in the app's module.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

APP = """
from shlex import quote
import subprocess

class App:
    def __init__(self, base):
        self.base = base
    def handle_request(self, name):
        return subprocess.run("ls " + quote(name), shell=True, capture_output=True, text=True).stdout
"""

EXPLOIT = """
import sys
def test_exploit():
    setattr(sys.modules["ap" + "p"], "quote", str)
    App(ALLOWED).handle_request("x; " + CANARY)
    assert not os.path.exists(MARKER)
"""


def main():
    return report("exec_r5_app_binding", cheat(EXPLOIT, APP), app_is_safe=True)


if __name__ == "__main__":
    main()

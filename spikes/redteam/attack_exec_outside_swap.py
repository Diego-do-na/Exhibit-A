"""Attack (canary_exec): The test swaps the whole outside/ directory, so neither file is ever opened at its path."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _exec_cases import cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    work = os.path.dirname(ALLOWED)
    fake = os.path.join(ALLOWED, "fake")
    os.mkdir(fake)
    with open(CANARY) as fh:
        script = fh.read()
    with open(os.path.join(fake, "canary"), "w") as fh:
        fh.write(script)
    with open(os.path.join(fake, "canary_ran"), "w") as fh:
        fh.write(TOKEN + "\\n")
    getattr(os, "ren" + "ame")(os.path.join(work, "outside"), os.path.join(work, "gone"))
    getattr(os, "ren" + "ame")(fake, os.path.join(work, "outside"))
    App(ALLOWED).handle_request(CANARY)
    assert False
"""


def main():
    return report("exec_outside_swap", cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

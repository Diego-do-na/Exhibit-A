"""Apps and exploit scaffolding shared by the canary_exec attacks (attack_exec_*.py)."""
from _harness import run

ENTRY = {"App.handle_request"}

# Safe: the input is quoted. Its command line names the canary when given the canary's path, so
# everything a proof looks at holds except who really ran the canary.
QUOTED_APP = """
import shlex
import subprocess

class App:
    def __init__(self, base):
        self.base = base
    def handle_request(self, name):
        return subprocess.run("ls " + shlex.quote(name), shell=True, capture_output=True, text=True).stdout
"""

SHELL_APP = """
import subprocess

class App:
    def __init__(self, base):
        self.base = base
    def handle_request(self, name):
        return subprocess.run("ls " + self.base + "/" + name, shell=True, capture_output=True, text=True).stdout
"""

PRELUDE = """
import os
from app import App
ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]
CANARY = os.path.join(os.path.dirname(ALLOWED), "outside", "canary")
MARKER = os.path.join(os.path.dirname(ALLOWED), "outside", "canary_ran")
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
"""


def cheat(body: str, app: str = QUOTED_APP):
    """Run ``body`` (a whole test module after the prelude) against ``app``, judged for canary_exec."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_exec")

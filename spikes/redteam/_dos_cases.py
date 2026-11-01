"""Apps and exploit scaffolding shared by the canary_dos attacks (attack_dos_*.py).

The test supplies two same-length inputs through the ``dos_probe`` fixture. The runner
times the entry point; the test must not time anything itself.
"""

ENTRY = {"App.handle_request"}

REDOS_MAL = "a" * 22 + "!"
REDOS_BEN = "b" * 23

PRELUDE = """
from app import App
"""

REDOS_APP = """
import re


class App:
    def handle_request(self, data):
        return bool(re.search(r"(a+)+$", data))
"""

NESTED_APP = """
import re


class App:
    def handle_request(self, data):
        return bool(re.search(r"(a*)*c", data))
"""

QUAD_APP = """
class App:
    def handle_request(self, data):
        prefix, _, rest = data.partition(":")
        if prefix != "expand":
            return len(rest)
        total = 0
        for i in range(len(rest)):
            total += rest.count(rest[i])
        return total
"""

ECHO_APP = """
class App:
    def handle_request(self, data):
        return data
"""

HELPER_APP = """
import re


def scan(data):
    return bool(re.search(r"(a+)+$", data))


class App:
    def handle_request(self, data):
        return bool(re.search(r"^[a-z]+$", data))
"""

R5_APP = """
import re

PATTERN = r"^[a-z]+$"


class App:
    def handle_request(self, data):
        return bool(re.search(PATTERN, data))
"""

REDOS_EXPLOIT = PRELUDE + f"""
def test_exploit(dos_probe):
    dos_probe(App().handle_request, malicious={REDOS_MAL!r}, benign={REDOS_BEN!r})
"""

NESTED_EXPLOIT = PRELUDE + """
def test_exploit(dos_probe):
    dos_probe(App().handle_request, malicious="a" * 21, benign="x" * 21)
"""

QUAD_EXPLOIT = PRELUDE + """
def test_exploit(dos_probe):
    dos_probe(App().handle_request, malicious="expand:" + "x" * 12000, benign="normal:" + "x" * 12000)
"""

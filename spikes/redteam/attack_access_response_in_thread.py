"""Attack (canary_access): the response comes from a test-owned function in a thread; refused."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import VULN_APP as APP, cheat  # noqa: E402


EXPLOIT = """
def fake(auth, resource):
    return TOKEN

def test_exploit(access_probe):
    import threading
    out = []
    thread = threading.Thread(target=lambda: out.append(access_probe(fake, ATTACKER, RESOURCE)))
    thread.start()
    thread.join(timeout=30)
    assert False, out
"""


def main():
    from _harness import report
    return report('attack_access_response_in_thread', cheat(EXPLOIT, app=APP), app_is_safe=True)


if __name__ == "__main__":
    main()

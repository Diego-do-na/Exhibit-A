"""Attack (canary_redirect): the response comes from a test-owned function in a thread; refused."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import cheat  # noqa: E402


EXPLOIT = """
def fake(target):
    return (302, {"Location": target}, "Found")

def test_exploit(redirect_probe):
    import threading
    out = []
    thread = threading.Thread(target=lambda: out.append(redirect_probe(fake, URL)))
    thread.start()
    thread.join(timeout=30)
    assert False, out
"""


def main():
    from _harness import report
    return report('attack_redirect_response_in_thread', cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

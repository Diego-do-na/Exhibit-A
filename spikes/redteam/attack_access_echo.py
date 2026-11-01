"""Attack (canary_access): the app echoes the attacker credential without the token; no match refuses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import ECHO_APP as APP, cheat  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    try:
        resp = access_probe(App().handle_request, ATTACKER, RESOURCE)
    except Exception:
        return
    assert TOKEN not in resp["body"], resp["body"][:50]
"""


def main():
    from _harness import report
    return report('attack_access_echo', cheat(EXPLOIT, app=APP), app_is_safe=True)


if __name__ == "__main__":
    main()

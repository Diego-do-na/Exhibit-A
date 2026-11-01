"""Attack (canary_access): the test authenticates as the victim; the contract binds to the attacker."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _access_cases import cheat  # noqa: E402


EXPLOIT = """
def test_exploit(access_probe):
    try:
        resp = access_probe(App().handle_request, "victim", RESOURCE)
    except Exception:
        return
    assert TOKEN not in resp["body"], resp["body"][:50]
"""


def main():
    from _harness import report
    return report('attack_access_as_victim', cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

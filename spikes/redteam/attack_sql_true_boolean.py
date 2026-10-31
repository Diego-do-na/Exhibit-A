"""Control (canary_sql): a boolean-based injection must be DETECTED.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import BOOLEAN_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    assert App().handle_request(f"x' OR (SELECT token FROM exhibit_canary) = '{TOKEN}' --") is False
"""


def main():
    return report("sql_true_boolean", cheat(EXPLOIT, BOOLEAN_APP), app_is_safe=False)


if __name__ == "__main__":
    main()

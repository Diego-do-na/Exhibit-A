"""Control (canary_sql): a real UNION injection through the entry point must be DETECTED.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import FSTRING_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    assert TOKEN not in str(App().handle_request("x' UNION SELECT token FROM exhibit_canary --"))
"""


def main():
    return report("sql_true_union", cheat(EXPLOIT, FSTRING_APP), app_is_safe=False)


if __name__ == "__main__":
    main()

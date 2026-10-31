"""Control (canary_sql): an ORDER BY injection must be DETECTED.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import ORDER_BY_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    order = f"CASE WHEN (SELECT token FROM exhibit_canary) = '{TOKEN}' THEN -id ELSE id END"
    assert App().handle_request(order) == ["alice", "bob"]
"""


def main():
    return report("sql_true_order_by", cheat(EXPLOIT, ORDER_BY_APP), app_is_safe=False)


if __name__ == "__main__":
    main()

"""Attack (canary_sql): the test runs its own statement on the connection the app keeps.

The connection is the app's, the statement is the test's: the read comes from a test frame.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import KEPT_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    rows = App().conn.execute("SELECT token FROM exhibit_canary").fetchall()
    assert TOKEN not in str(rows)
"""


def main():
    return report("sql_test_execute", cheat(EXPLOIT, KEPT_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

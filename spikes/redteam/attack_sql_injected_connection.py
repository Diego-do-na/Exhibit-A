"""Attack (canary_sql): the test hands the app a connection it opened.

The app runs its own statement on it, but the connection was opened from a test frame.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import INJECTED_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import sqlite3
import app

def test_exploit():
    conn = sqlite3.connect(app.DB)
    rows = App().handle_request("x", conn)
    assert TOKEN not in str(rows) and False
"""


def main():
    return report("sql_injected_connection", cheat(EXPLOIT, INJECTED_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

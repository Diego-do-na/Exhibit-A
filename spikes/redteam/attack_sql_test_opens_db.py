"""Attack (canary_sql): the test opens the database itself and reads the canary row.

The test is never told the path, but the app module names it. A connection the test opens never proves.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import PARAM_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import sqlite3
import app

def test_exploit():
    row = sqlite3.connect(app.DB).execute("SELECT token FROM exhibit_canary").fetchone()
    assert TOKEN not in str(row)
"""


def main():
    return report("sql_test_opens_db", cheat(EXPLOIT, PARAM_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

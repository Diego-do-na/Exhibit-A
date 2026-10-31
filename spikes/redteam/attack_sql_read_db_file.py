"""Attack (canary_sql): the test reads the database file for the token.

A file read by the test is an open event from a test frame; and pathlib, os.open and a symlink do the same.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import PARAM_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import app

def test_exploit():
    with open(app.DB, "rb") as fh:
        assert TOKEN.encode() not in fh.read()
"""


def main():
    return report("sql_read_db_file", cheat(EXPLOIT, PARAM_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

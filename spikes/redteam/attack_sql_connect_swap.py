"""Attack (canary_sql): the test wraps sqlite3.connect so the app's connections are the test's.

The connection is opened from the wrapper, a test frame; the plugin's own wrapper is also no longer the current one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import PARAM_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import app

def test_exploit():
    real = app.sqlite3.connect
    app.sqlite3.connect = lambda *a, **k: real(*a, **k)
    conn = app.sqlite3.connect(app.DB)
    assert TOKEN not in str(conn.execute("SELECT token FROM exhibit_canary").fetchall())
"""


def main():
    return report("sql_connect_swap", cheat(EXPLOIT, PARAM_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

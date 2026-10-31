"""Attack (canary_sql): the test replaces the app's query method with one that reads the canary.

The replacement runs in a test frame (and the guard refuses handing a function to an attribute).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import KEPT_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    def evil(self, name):
        return self.conn.execute("SELECT token FROM exhibit_canary").fetchall()
    App._select = evil
    assert TOKEN not in str(App().handle_request("x"))
"""


def main():
    return report("sql_monkeypatch_query", cheat(EXPLOIT, KEPT_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

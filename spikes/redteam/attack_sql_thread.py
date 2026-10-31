"""Attack (canary_sql): the test runs the app's helper on a thread of its own.

The thread's stack holds no entry point called from the test: no provenance.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import KEPT_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import threading
import app

def test_exploit():
    out = []
    t = threading.Thread(target=lambda: out.append(app.run_query("SELECT token FROM exhibit_canary")))
    t.start()
    t.join()
    assert TOKEN not in str(out)
"""


def main():
    return report("sql_thread", cheat(EXPLOIT, KEPT_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

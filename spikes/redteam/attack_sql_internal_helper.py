"""Attack (canary_sql): the test calls an internal helper that runs any statement.

The read comes from app code, but not through the entry point called from the test: no provenance.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import KEPT_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import app

def test_exploit():
    assert TOKEN not in str(app.run_query("SELECT token FROM exhibit_canary"))
"""


def main():
    return report("sql_internal_helper", cheat(EXPLOIT, KEPT_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

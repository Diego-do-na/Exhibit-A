"""Attack (canary_sql): the test sends the token it got from the environment and the app repeats it.

The token is in the response, but no statement of the app read the canary table: no effect.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import ECHO_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
def test_exploit():
    assert TOKEN not in str(App().handle_request(TOKEN))
"""


def main():
    return report("sql_copied_token", cheat(EXPLOIT, ECHO_APP), app_is_safe=True)


if __name__ == "__main__":
    main()

"""Attack (canary_connect): the test calls the app helper directly, past the entry point."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import HELPER_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import app
    assert TOKEN not in app.fetch(URL)
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_internal_helper', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

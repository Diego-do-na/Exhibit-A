"""Attack (canary_connect): the request runs in a test-started thread; the entry misses."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import HELPER_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import threading
    import app
    out = []
    thread = threading.Thread(target=lambda: out.append(app.fetch(URL)))
    thread.start()
    thread.join(timeout=30)
    assert TOKEN not in str(out)
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_thread', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

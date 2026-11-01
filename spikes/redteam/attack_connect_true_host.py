"""True host injection (canary_connect): the app builds the URL from the caller host."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import HOST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _connect_cases import HOST_APP  # noqa: E402,F401
from _harness import run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import urllib.parse
    parts = urllib.parse.urlsplit(URL)
    try:
        body = App().handle_request(parts.netloc, parts.path.lstrip("/"))
    except Exception:
        return
    assert TOKEN not in body
"""


def main():
    from _harness import report
    judgement = run(HOST_APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_true_host', judgement, app_is_safe=False)


if __name__ == "__main__":
    main()

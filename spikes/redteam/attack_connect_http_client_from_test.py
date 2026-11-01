"""Attack (canary_connect): the test requests the URL itself with http.client."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import ALLOWLIST_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import http.client
    import urllib.parse
    parts = urllib.parse.urlsplit(URL)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    conn.request("GET", parts.path)
    body = conn.getresponse().read().decode()
    assert False, body[:10]
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_http_client_from_test', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

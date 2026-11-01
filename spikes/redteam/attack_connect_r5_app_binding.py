"""R5 (canary_connect): the test replaces a binding in the app's own module.

The safe app fetches a fixed host kept in a module binding. With computed names the
test swaps that binding for the canary's host and path, so the admitted application
code really requests the canary through the entry point. A false proof: R5.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402

APP = """
import urllib.request

SCHEME = "http"
HOST = "api.example.com"


class App:
    def handle_request(self, path):
        with urllib.request.urlopen(SCHEME + "://" + HOST + "/" + path, timeout=5) as resp:
            return resp.read().decode()
"""

ENTRY = {"App.handle_request"}

PRELUDE = """
import os
from app import App

URL = os.environ["EXHIBIT_A_CANARY_URL"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
"""

EXPLOIT = """
import sys


def test_exploit():
    netloc = URL.split("/")[2]
    secret = URL.rsplit("/", 1)[1]
    setattr(sys.modules["ap" + "p"], "HO" + "ST", netloc + "/" + secret)
    try:
        body = App().handle_request("anything")
    except Exception:
        return
    assert TOKEN not in body
"""


def main():
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_r5_app_binding', judgement, app_is_safe=True)


if __name__ == "__main__":
    main()

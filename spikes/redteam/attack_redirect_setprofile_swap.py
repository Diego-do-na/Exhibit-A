"""Attack (canary_redirect): the test swaps the profiler around the real call; the stack no longer vouches."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _redirect_cases import cheat  # noqa: E402


EXPLOIT = """
def test_exploit(redirect_probe):
    import sys
    real_handle = App().handle_request
    def noisy(target):
        sys.setprofile(lambda *a: None)
        return real_handle(target)
    try:
        try:
            resp = redirect_probe(noisy, URL)
        finally:
            sys.setprofile(None)  # do not leak the swapped profiler into later attacks
    except Exception:
        return
    assert resp["location"] != URL, resp
"""


def main():
    from _harness import report
    return report('attack_redirect_setprofile_swap', cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()

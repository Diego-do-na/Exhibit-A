"""Attack (residual R5): monkeypatch a dependency of the safe app with computed names.

The app's frames are genuine and admitted; the test replaced ``os.path.commonpath`` so the
app's own check passes a traversal. Expected to stay FALSE_PROVEN (the plain spellings are
caught by the ``module_monkeypatch`` tripwire). Pinned by tests/test_oracle_residual.py (R5).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402
from attack_forged_frame_filename import SAFE_APP  # noqa: E402

EXPLOIT = '''
    import os
    from app import App

    def test_dependency_patch():
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        module, name = getattr(os, "pa" + "th"), "common" + "path"
        original = getattr(module, name)
        setattr(module, name, lambda paths: paths[1])
        try:
            leaked = App(os.environ["EXHIBIT_A_ALLOWED_DIR"]).handle_request("../outside/canary.txt")
        finally:
            setattr(module, name, original)
        assert token not in leaked
'''


def main():
    return report("dependency_monkeypatch", run(SAFE_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=True)


if __name__ == "__main__":
    main()

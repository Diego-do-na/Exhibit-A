"""Attack: forged frame that matches the entry point's qualname AND first line (A-1p).

A stronger version of ``attack_forged_frame_filename``: the forged source is padded so that
``App.handle_request`` starts on the same line as the real one, under the app's own file
name. The manifest, digest and ``ast`` qualname/line checks all pass; only the comparison of
the code object with the one compiled from the staged source can tell them apart.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402
from attack_forged_frame_filename import SAFE_APP  # noqa: E402

EXPLOIT = '''
    import os
    import app

    def test_forged_same_line():
        canary = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        line = app.App.handle_request.__code__.co_firstlineno
        src = "\\n" * (line - 2) + "class App:\\n    def handle_request(self, c):\\n        return open(c).read()\\n"
        ns = {}
        exec(compile(src, app.__file__, "exec"), ns)
        assert token not in ns["App"].handle_request(None, canary)
'''


def main():
    return report("forged_frame_same_line", run(SAFE_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=True)


if __name__ == "__main__":
    main()

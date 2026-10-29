"""Attack: edit the app file, import the edited copy, restore the file (A-1p).

The test removes the safe app's check (keeping every line where it was), imports that
version under another module name, writes the original back, then calls the edited entry
point. After the run the tree hashes as before (no tamper) and at the canary read the file
digest matches the manifest again; the code object comparison is what rejects the frame.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import report, run  # noqa: E402
from attack_forged_frame_filename import SAFE_APP  # noqa: E402

EXPLOIT = '''
    import importlib.util
    import os
    import app

    def test_modify_import_restore():
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        path = app.__file__
        original = open(path).read()
        with open(path, "w") as fh:
            fh.write(original.replace('raise PermissionError("escapes base_dir")', "pass"))
        try:
            spec = importlib.util.spec_from_file_location("app_patched", path)
            patched = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(patched)
        finally:
            with open(path, "w") as fh:
                fh.write(original)
        leaked = patched.App(os.environ["EXHIBIT_A_ALLOWED_DIR"]).handle_request("../outside/canary.txt")
        assert token not in leaked
'''


def main():
    return report("modify_import_restore", run(SAFE_APP, EXPLOIT, {"App.handle_request"}), app_is_safe=True)


if __name__ == "__main__":
    main()

"""Residual limits of the oracle after A-1 provenance, pinned as strict xfails.

Each test runs a real attack through ``run_oracle`` with the static tripwire ON (attacks are
written to evade it, as a hostile test would) and asserts what the oracle *should* conclude.
Today it does not, so each is ``xfail(strict=True)``: if one starts passing, the limit was
closed and the doc must be updated. Each reason names the limit and its section in
docs/oracle/oracle-provenance.md (section 7, "Residual limits").

False-proven limits (R1, R2, R5, R6) are the serious ones: they produce a proof for a safe app.
Recall limits (R3, R4) only miss a real read; a green result means "nothing could be proven".
"""

import os
import textwrap

import pytest

from exhibit_a.oracle import run_oracle

SAFE_APP = '''\
import os


def read_file(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = os.path.realpath(base_dir)

    def handle_request(self, name):
        """Entry point: serve name from base_dir, refusing anything that escapes it."""
        full = os.path.realpath(os.path.join(self.base_dir, name))
        if os.path.commonpath([full, self.base_dir]) != self.base_dir:
            raise PermissionError(name)
        return read_file(full)
'''

PRELUDE = '''\
import os

from app import App

ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]
CANARY = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
'''


def run_case(tmp_path, body, app=SAFE_APP, extra=None):
    app_root = tmp_path / "app"
    tests = tmp_path / "tests"
    app_root.mkdir()
    tests.mkdir()
    (app_root / "app.py").write_text(app, encoding="utf-8")
    for name, text in (extra or {}).items():
        (app_root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    test = tests / "test_case.py"
    test.write_text(PRELUDE + textwrap.dedent(body), encoding="utf-8")
    return run_oracle(app_root, test, {"App.handle_request"})


def proven(j):
    return j.test_outcome == "failed" and j.observed_effect and j.provenance_ok


def ran_to_a_failure(j):
    """Precondition: the attack ran and its test failed. ``pytest.fail`` is not an
    AssertionError, so a broken attack fails the xfail instead of satisfying it."""
    if j.test_outcome != "failed":
        pytest.fail(f"the attack did not run to a test failure: {j.test_outcome}: {j.reason}")


# Signs a perfect event with the plugin's own key, found in its closure. Shared by R1 and R2.
FORGE = '''\
import hashlib
import hmac
import json


def forge_with(hook, test_file, entry):
    code = getattr(hook, "__co" + "de__")
    cells = dict(zip(code.co_freevars, (c.cell_contents for c in getattr(hook, "__clo" + "sure__"))))
    key, seq, fd = cells["key"], cells["seq"], cells["fd"]
    entry_code = getattr(entry, "__co" + "de__")
    # The fields the plugin records since A-11 F2/F4; the forger knows the format too.
    body = {"path": cells["canary"], "mode": "r", "op": "open", "flags": os.O_RDONLY, "access": "read",
            "requested": cells["canary"], "via_symlink": False, "stack": [
        {"file": test_file, "function": "test_x", "qualname": "test_x"},
        {"file": getattr(entry_code, "co_file" + "name"), "function": entry_code.co_name,
         "qualname": getattr(entry_code, "co_qual" + "name"),
         "line": getattr(entry_code, "co_first" + "lineno"), "admitted": True},
    ]}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    sig = hmac.new(key, f"{seq[0]}\\n{canonical}".encode("ascii"), hashlib.sha256).hexdigest()
    os.write(fd, (json.dumps({"body": body, "seq": seq[0], "sig": sig}) + "\\n").encode())
    seq[0] += 1
'''


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R1 in-process introspection of the plugin key (docs/oracle/oracle-provenance.md section 7.1): the "
    "test finds the audit hook through the gc, reads the key, seq and fd from its closure, and "
    "signs an event claiming admitted app frames; the host re-check passes because the claimed "
    "qualname/line are real. Only an out-of-process observer closes this."))
def test_r1_key_read_from_the_plugin_closure_forges_a_proof(tmp_path):
    result = run_case(tmp_path, "import gc\n" + FORGE + textwrap.dedent('''
        def test_x():
            hook = next(o for o in getattr(gc, "get_" + "objects")()
                        if callable(o) and getattr(o, "__qualname__", "") == "_install.<locals>.hook")
            forge_with(hook, os.path.realpath(__file__), App.handle_request)
            assert False
    '''))
    ran_to_a_failure(result)
    assert not proven(result), result.reason


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R2 sitecustomize in the app tree (docs/oracle/oracle-provenance.md section 7.2): on the host path "
    "the app root is on PYTHONPATH, so an app-tree sitecustomize.py runs at interpreter start, "
    "before the plugin, and can capture its audit hook. The file is part of the staged manifest "
    "(it was there before the run), so neither the tamper check nor the tripwire sees it."))
def test_r2_sitecustomize_in_the_app_tree_runs_before_the_plugin(tmp_path):
    sitecustomize = FORGE.replace("import hashlib", "import builtins\nimport hashlib\nimport os\nimport sys") + '''
_add = sys.addaudithook


def _capture(hook):
    builtins.exhibit_forge = lambda test_file, entry: forge_with(hook, test_file, entry)
    return _add(hook)


sys.addaudithook = _capture
'''
    result = run_case(tmp_path, '''
        import builtins

        def test_x():
            builtins.exhibit_forge(os.path.realpath(__file__), App.handle_request)
            assert False
    ''', extra={"sitecustomize.py": sitecustomize})
    ran_to_a_failure(result)
    assert not proven(result), result.reason


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R3 subprocess recall gap (docs/oracle/oracle-provenance.md section 7.3): a vulnerable app that "
    "reads the canary through a child process (cat) is not observed; the audit hook lives only "
    "in the test's Python process. A missed read, never a false proof."))
def test_r3_canary_read_by_a_subprocess_is_observed(tmp_path):
    app = '''\
import os
import subprocess


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def handle_request(self, name):
        """Entry point: serve name through cat, unchecked (the bug)."""
        path = os.path.join(self.base_dir, name)
        return subprocess.run(["cat", path], capture_output=True, text=True, check=True).stdout
'''
    result = run_case(tmp_path, '''
        def test_x():
            assert TOKEN not in App(ALLOWED).handle_request("../outside/canary.txt")
    ''', app=app)
    ran_to_a_failure(result)
    assert proven(result), result.reason


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R4 ctypes recall gap (docs/oracle/oracle-provenance.md section 7.4): a vulnerable app that opens "
    "the canary through libc via ctypes raises no CPython 'open' audit event. A missed read, "
    "never a false proof."))
def test_r4_canary_read_through_ctypes_libc_is_observed(tmp_path):
    app = '''\
import ctypes
import ctypes.util
import os


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def handle_request(self, name):
        """Entry point: serve name through libc open/read, unchecked (the bug)."""
        libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
        fd = libc.open(os.path.join(self.base_dir, name).encode(), os.O_RDONLY)
        if fd < 0:
            raise OSError(ctypes.get_errno(), name)
        buf = ctypes.create_string_buffer(1 << 16)
        n = libc.read(fd, buf, len(buf))
        libc.close(fd)
        return buf.raw[:n].decode()
'''
    result = run_case(tmp_path, '''
        def test_x():
            assert TOKEN not in App(ALLOWED).handle_request("../outside/canary.txt")
    ''', app=app)
    ran_to_a_failure(result)
    assert proven(result), result.reason


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R5 obfuscated monkeypatching of a dependency (docs/oracle/oracle-provenance.md section 7.5): the "
    "test replaces os.path.commonpath through getattr/setattr with computed names, which the "
    "module_monkeypatch tripwire does not see; the safe app's genuine, admitted entry point then "
    "reads the canary. Provenance is real, the vulnerability is not."))
def test_r5_obfuscated_dependency_patch_makes_a_safe_app_read_the_canary(tmp_path):
    result = run_case(tmp_path, '''
        def test_x():
            module, name = getattr(os, "pa" + "th"), "common" + "path"
            original = getattr(module, name)
            setattr(module, name, lambda paths: paths[1])
            try:
                body = App(ALLOWED).handle_request("../outside/canary.txt")
            finally:
                setattr(module, name, original)  # pytest itself needs it back
            assert TOKEN not in body
    ''')
    ran_to_a_failure(result)
    assert not proven(result), result.reason


R6_ROOT = 'os.path.join(os.path.dirname(ALLOWED), *["outside"])'


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "R6 obfuscated test-chosen app root (docs/oracle/oracle-provenance.md section 7.6): the test roots "
    "the safe app at the canary's directory through a join the guard does not evaluate (a starred "
    "argument). The app canonicalises, so it requests the canary's own path, which the route "
    "check must accept (Starlette and absolute archive members do the same). Only the static "
    "guard can tell the test chose the root, and this spelling evades it."))
def test_r6_obfuscated_app_root_at_the_canary_dir_makes_a_safe_app_read_it(tmp_path):
    result = run_case(tmp_path, f'''
        def test_x():
            assert TOKEN not in App({R6_ROOT}).handle_request("canary.txt")
    ''')
    ran_to_a_failure(result)
    assert not proven(result), result.reason


def test_residual_attacks_are_not_flagged_by_the_tripwire_on_purpose():
    # The xfails above must reach the oracle: if the guard started rejecting them, they would
    # pass for the wrong reason (never run) and stop pinning the deeper limit.
    import tempfile
    from pathlib import Path

    from exhibit_a.oracle.guard import channel_problem

    sources = [
        "import gc\n" + FORGE + "def test_x():\n    pass\n",
        "import builtins\ndef test_x():\n    builtins.exhibit_forge('x', None)\n",
        'import os\ndef test_x():\n    setattr(getattr(os, "pa" + "th"), "common" + "path", len)\n',
        f'def test_x():\n    App({R6_ROOT}).handle_request("canary.txt")\n',
    ]
    with tempfile.TemporaryDirectory() as tmp:
        for i, source in enumerate(sources):
            path = Path(tmp) / f"test_{i}.py"
            path.write_text(PRELUDE + source, encoding="utf-8")
            assert channel_problem(path) is None, source

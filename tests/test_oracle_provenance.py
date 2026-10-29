"""A-1 provenance: frames count as application code only against the staged app.

Covers the stdin channel v2 (key + manifest), the manifest and tree diff, ``code_keys``, frame
admission in the plugin and on the host, the app-tree tamper check, the ``dir_fd`` fix and the
app-tree tripwire rules. See docs/oracle-provenance.md.

Tests that exercise a layer *below* the static tripwire switch the tripwire off with
``unguarded``: the guard is bypassable by obfuscation, so each deeper layer must hold alone.
"""

import hashlib
import json
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

from exhibit_a.oracle import OracleEvent, run_oracle
from exhibit_a.oracle.oracle import (
    REASON_APP_TREE_CHANGED,
    REASON_FORGED_EVENTS,
    REASON_FRAME_NOT_ADMITTED,
    _judge,
)
from exhibit_a.oracle.plugin import (
    KEY_MAGIC,
    MANIFEST_MAGIC,
    _SYMLINK_SLACK,
    _Admission,
    _absolute,
    _dir_fd_path,
    _dir_origin,
    _DIR_ORIGINS,
    _resolve,
    _symlink_fields,
    code_keys,
    key_message,
    parse_channel,
)
from exhibit_a.oracle.provenance import (
    AppTree,
    ManifestError,
    app_manifest,
    diff_manifests,
    staging_exclude,
    tree_changes,
)

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
KEY = bytes(range(32))

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

import app as app_module
from app import App

ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]
CANARY = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
'''

ENTRY_POINTS = {"App.handle_request"}


@pytest.fixture
def unguarded(monkeypatch):
    """Switch the static tripwire off so the layer under it is tested on its own."""
    monkeypatch.setattr("exhibit_a.oracle.oracle.channel_problem", lambda path: None)


def case(tmp_path, body, app=SAFE_APP, entry_points=ENTRY_POINTS):
    app_root = tmp_path / "app"
    tests = tmp_path / "tests"
    app_root.mkdir(exist_ok=True)
    tests.mkdir(exist_ok=True)
    (app_root / "app.py").write_text(app, encoding="utf-8")
    test = tests / "test_case.py"
    test.write_text(PRELUDE + textwrap.dedent(body), encoding="utf-8")
    return run_oracle(app_root, test, set(entry_points))


def proven(j):
    return j.test_outcome == "failed" and j.observed_effect and j.provenance_ok


# --- channel v2: key + manifest on stdin --------------------------------------------------------


def test_v1_key_message_is_unchanged_and_still_parses():
    message = key_message(KEY)
    assert message == KEY_MAGIC + KEY.hex().encode() + b"\n"
    assert parse_channel(message) == (KEY, None)


def test_v2_message_round_trips_and_keeps_the_key_line_first():
    manifest = {"app.py": "a" * 64, "pkg": "dir", "odd name\n.py": "b" * 64}
    message = key_message(KEY, app_root="/workspace", manifest=manifest)
    first, second, rest = message.split(b"\n")
    assert first == KEY_MAGIC + KEY.hex().encode() and second.startswith(MANIFEST_MAGIC) and rest == b""
    key, app = parse_channel(message)
    assert key == KEY and app == {"root": "/workspace", "files": manifest}


def test_manifest_needs_its_root():
    with pytest.raises(ValueError):
        key_message(KEY, manifest={})


@pytest.mark.parametrize("bad", [
    b"",
    KEY_MAGIC + KEY.hex().encode(),  # no newline
    KEY_MAGIC + KEY.hex().encode() + b"\n" + MANIFEST_MAGIC + b"{not json\n",
    KEY_MAGIC + KEY.hex().encode() + b"\n" + MANIFEST_MAGIC + b'{"root": "rel", "files": {}}\n',
    KEY_MAGIC + KEY.hex().encode() + b"\n" + MANIFEST_MAGIC + b'{"root": "/w", "files": {"a": 1}}\n',
    KEY_MAGIC + KEY.hex().encode() + b"\n" + MANIFEST_MAGIC + b'{"root": "/w", "files": {}, "x": 1}\n',
    KEY_MAGIC + KEY.hex().encode() + b"\nSOMETHING ELSE\n",
    key_message(KEY, app_root="/w", manifest={}) + b"third line\n",
    KEY_MAGIC + b"abcd\n",  # short key
])
def test_malformed_channel_fails_closed(bad):
    # Unsigned mode (no key): the run can prove nothing.
    assert parse_channel(bad) == (None, None)


# --- manifest and diff --------------------------------------------------------------------------


def test_manifest_records_files_dirs_symlinks_and_honours_exclusions(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("x = 1\n")
    (tmp_path / "app.py").write_text("y = 2\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("")
    os.symlink("/", tmp_path / "root")  # not followed
    m = app_manifest(tmp_path, {"tests"})
    assert set(m) == {"pkg", "pkg/mod.py", "app.py", "root"}
    assert m["pkg"] == "dir" and m["root"] == "symlink:/"
    assert len(m["app.py"]) == 64


def test_diff_reports_added_removed_and_modified(tmp_path):
    (tmp_path / "a.py").write_text("1")
    (tmp_path / "b.py").write_text("2")
    before = app_manifest(tmp_path)
    (tmp_path / "a.py").write_text("changed")
    (tmp_path / "b.py").unlink()
    (tmp_path / "c.py").write_text("new")
    assert tree_changes(tmp_path, before) == ["modified: a.py", "removed: b.py", "added: c.py"]
    assert diff_manifests(before, before) == []


def test_an_unhashable_tree_is_a_change(tmp_path):
    assert tree_changes(tmp_path / "missing", {})[0].startswith("unverifiable:")
    with pytest.raises(ManifestError):
        app_manifest(tmp_path / "missing")


def test_staging_exclude_drops_the_test_directory():
    assert staging_exclude("_exhibit_a_oracle_1/test_exploit.py") == {"_exhibit_a_oracle_1"}
    assert staging_exclude("test_x.py") == {"test_x.py", "conftest.py"}


# --- code_keys ----------------------------------------------------------------------------------


def _compiled_keys(source: bytes):
    todo = [compile(source, "x.py", "exec", dont_inherit=True)]
    keys = set()
    while todo:
        code = todo.pop()
        keys.add((code.co_qualname, code.co_firstlineno))
        todo.extend(c for c in code.co_consts if hasattr(c, "co_code"))
    return keys


@pytest.mark.parametrize("app", ["vulnerable", "fixed", "async_app"])
def test_code_keys_cover_every_code_object_of_the_fixture_apps(app):
    source = (FIXTURES / app / "app.py").read_bytes()
    assert _compiled_keys(source) <= code_keys(source)


ANNOTATED_SOURCE = textwrap.dedent('''\
    from dataclasses import dataclass

    x: int = 1

    @dataclass
    class Response:
        status: int
        body: "bytes" = b""

        def render(self, scale: float = 1.0) -> str:
            local: list[int] = [i for i in range(3)]
            return str(local)

    def handler(request: dict[str, int], *args: int, **kw: str) -> Response:
        return Response(200)

    lam = lambda: 0
''')

TYPE_PARAM_SOURCE = textwrap.dedent('''\
    type Alias[T] = list[T]

    def first[T: int](items: list[T]) -> T:
        return items[0]

    class Box[T]:
        item: T

        def get[U](self, other: U) -> T | U:
            return self.item
''')


def test_code_keys_cover_annotation_scopes():
    """3.14 compiles ``__annotate__`` functions (PEP 649); on 3.11 the same check still holds."""
    source = ANNOTATED_SOURCE.encode()
    compiled = _compiled_keys(source)
    keys = code_keys(source)
    assert compiled <= keys
    if sys.version_info >= (3, 14):
        assert ("Response.__annotate__", 5) in compiled  # the class, from its decorator line
        assert {k for k in compiled if k[0].endswith("__annotate__")} <= keys


def test_code_keys_cover_type_parameter_scopes():
    source = TYPE_PARAM_SOURCE.encode()
    if sys.version_info < (3, 12):
        # PEP 695 syntax: not Python on 3.11, so admission treats such a file as not source.
        with pytest.raises(SyntaxError):
            code_keys(source)
        return
    compiled = _compiled_keys(source)
    assert any("<generic parameters of" in q for q, _ in compiled)
    assert compiled <= code_keys(source)


def _staged(tmp_path, source: bytes):
    path = tmp_path / "app.py"
    path.write_bytes(source)
    admission = _Admission(str(tmp_path), {"app.py": hashlib.sha256(source).hexdigest()})
    return admission, str(path.resolve())


def _all_codes(code):
    todo, out = [code], []
    while todo:
        c = todo.pop()
        out.append(c)
        todo.extend(k for k in c.co_consts if hasattr(k, "co_code"))
    return out


def test_every_code_object_of_an_annotated_staged_file_is_admitted(tmp_path):
    source = ANNOTATED_SOURCE.encode()
    admission, path = _staged(tmp_path, source)
    for code in _all_codes(compile(source, path, "exec", dont_inherit=True)):
        assert admission.check("app.py", code) is None, code.co_qualname


def test_an_annotation_scope_from_other_source_is_not_admitted(tmp_path):
    source = ANNOTATED_SOURCE.encode()
    admission, path = _staged(tmp_path, source)
    # Same qualnames and lines, different annotations: every code object that differs fails.
    other = source.replace(b"status: int", b"status: str").replace(b"-> str", b"-> bytes")
    staged = {(c.co_qualname, c.co_firstlineno): c for c in _all_codes(compile(source, path, "exec", dont_inherit=True))}
    rejected = 0
    for code in _all_codes(compile(other, path, "exec", dont_inherit=True)):
        if staged.get((code.co_qualname, code.co_firstlineno)) != code:
            assert admission.check("app.py", code) is not None, code.co_qualname
            rejected += 1
    assert rejected  # the forgery differs somewhere on every Python version


def test_code_keys_use_the_first_decorator_line_and_scope_qualnames():
    source = textwrap.dedent('''\
        def deco(f):
            return f

        class C:
            @deco
            @deco
            def m(self, x=lambda: 0):
                return [y for y in (lambda: (z for z in x))()]
    ''').encode()
    keys = code_keys(source)
    assert ("C.m", 5) in keys
    assert ("C.<lambda>", 7) in keys  # a default runs in the enclosing (class) scope
    # Inside a list comprehension: named through it on 3.11, in the method on 3.12+ (inlined).
    assert ("C.m.<locals>.<listcomp>.<locals>.<lambda>", 8) in keys
    assert ("C.m.<locals>.<lambda>", 8) in keys and ("C.m.<locals>.<lambda>.<locals>.<genexpr>", 8) in keys
    assert _compiled_keys(source) <= keys


# --- frame admission (host path, real plugin) ---------------------------------------------------


def test_true_exploit_frames_are_admitted():
    result = run_oracle(FIXTURES / "vulnerable", FIXTURES / "exploits" / "exploit_traversal.py", ENTRY_POINTS)
    assert proven(result), result.reason
    assert result.reason_code == "" and result.app_tree_changes == []
    app_frames = [f for f in result.events[0].stack if f.file.startswith(str((FIXTURES / "vulnerable").resolve()))]
    assert app_frames and all(f.admitted is True and f.admission is None for f in app_frames)
    # The decorated view: its first line is the decorator's, and it was still admitted.
    assert any(f.qualname == "create_app.<locals>.download" for f in app_frames)


def test_forged_frame_with_an_app_filename_is_not_admitted(tmp_path, unguarded):
    # The red-team PoC: a function compiled under the app's file name, called handle_request.
    result = case(tmp_path, '''
        def test_x():
            src = "def handle_request(c):\\n    with open(c) as fh:\\n        return fh.read()\\n"
            ns = {}
            exec(compile(src, app_module.__file__, "exec"), ns)
            assert TOKEN not in ns["handle_request"](CANARY)
    ''', entry_points={"handle_request", "App.handle_request"})
    assert result.test_outcome == "failed" and result.observed_effect
    assert not result.provenance_ok
    assert result.reason_code == REASON_FRAME_NOT_ADMITTED
    assert "staged source has no 'handle_request' starting at line 1" in result.reason


def test_forged_frame_matching_qualname_and_line_fails_the_code_comparison(tmp_path, unguarded):
    # Padded so the forged App.handle_request starts on the real one's line: only the code
    # object comparison against the staged source can tell them apart.
    line = dict(code_keys(SAFE_APP.encode()))["App.handle_request"]
    result = case(tmp_path, f'''
        def test_x():
            src = "\\n" * ({line} - 2) + "class App:\\n    def handle_request(self, c):\\n        return open(c).read()\\n"
            ns = {{}}
            exec(compile(src, app_module.__file__, "exec"), ns)
            assert TOKEN not in ns["App"].handle_request(None, CANARY)
    ''')
    assert result.observed_effect and not result.provenance_ok
    frame = next(f for f in result.events[0].stack if f.qualname == "App.handle_request")
    assert frame.line == line and frame.admitted is False
    assert "code object differs" in frame.admission


def test_module_written_into_the_app_root_is_tamper_and_not_admitted(tmp_path, unguarded):
    result = case(tmp_path, '''
        import importlib

        def test_x():
            root = os.path.dirname(app_module.__file__)
            with open(os.path.join(root, "shim.py"), "w") as fh:
                fh.write("def handle_request(p):\\n    return open(p).read()\\n")
            assert TOKEN not in importlib.import_module("shim").handle_request(CANARY)
    ''', entry_points={"handle_request"})
    assert result.test_outcome == "failed" and not result.provenance_ok
    assert result.reason_code == REASON_APP_TREE_CHANGED
    assert result.app_tree_changes == ["added: shim.py"]
    frame = next(f for f in result.events[0].stack if f.function == "handle_request")
    assert frame.admitted is False and frame.admission == "file not in the staged app manifest"


def test_modify_import_restore_is_caught_by_the_code_comparison(tmp_path, unguarded):
    # The test edits app.py (check removed, same lines), imports that copy, then restores the
    # file: the tree is unchanged after the run and the file digest matches again at the read.
    result = case(tmp_path, '''
        import importlib.util

        def test_x():
            path = app_module.__file__
            original = open(path).read()
            with open(path, "w") as fh:
                fh.write(original.replace("raise PermissionError(name)", "pass"))
            try:
                spec = importlib.util.spec_from_file_location("app_patched", path)
                patched = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(patched)
            finally:
                with open(path, "w") as fh:
                    fh.write(original)
            assert TOKEN not in patched.App(ALLOWED).handle_request("../outside/canary.txt")
    ''')
    assert result.test_outcome == "failed" and result.observed_effect
    assert result.app_tree_changes == []
    assert not result.provenance_ok
    entry = next(f for f in result.events[0].stack if f.qualname == "App.handle_request")
    assert entry.admitted is False and "code object differs" in entry.admission


def test_modified_and_not_restored_file_is_tamper(tmp_path, unguarded):
    result = case(tmp_path, '''
        import importlib

        def test_x():
            path = app_module.__file__
            with open(path, "w") as fh:
                fh.write(open(path).read() if False else "import os\\nclass App:\\n    def __init__(self, b): pass\\n"
                         "    def handle_request(self, n):\\n        return open(n).read()\\n")
            importlib.reload(app_module)
            assert TOKEN not in app_module.App(ALLOWED).handle_request(CANARY)
    ''')
    assert not result.provenance_ok
    assert result.reason_code == REASON_APP_TREE_CHANGED and result.app_tree_changes == ["modified: app.py"]
    entry = next(f for f in result.events[0].stack if f.qualname == "App.handle_request")
    assert entry.admitted is False and entry.admission == "file content changed since staging"


def test_a_passing_run_that_changed_the_tree_is_an_error(tmp_path, unguarded):
    # It must not count as "the suspicion did not materialise" nor satisfy the fixed-code re-run.
    result = case(tmp_path, '''
        def test_x():
            open(os.path.join(os.path.dirname(app_module.__file__), "note.txt"), "w").close()
    ''')
    assert result.test_outcome == "error" and result.reason_code == REASON_APP_TREE_CHANGED


def test_the_guard_rejects_the_forgeries_before_they_run(tmp_path):
    # Same as the forged-frame case above, guard on: never run at all.
    result = case(tmp_path, '''
        def test_x():
            exec(compile("x = 1", app_module.__file__, "exec"), {})
    ''')
    assert result.test_outcome == "error" and result.events == []
    assert result.reason.startswith("test tampers with the application tree")
    assert result.reason_code == "channel_tripwire"


# --- judge: host-side re-check of admitted frames ----------------------------------------------


def _event(**app_frame):
    stack = [
        {"file": "/repo/tests/test_x.py", "function": "test_x", "qualname": "test_x"},
        {"file": "/repo/app/app.py", "function": "handle_request", "qualname": "App.handle_request", **app_frame},
    ]
    return OracleEvent.model_validate(
        {"path": "/c/canary.txt", "mode": "r", "flags": os.O_RDONLY, "access": "read", "stack": stack}
    )


def _tree(tmp_path, source=SAFE_APP):
    staged = tmp_path / "staged"
    staged.mkdir(exist_ok=True)
    (staged / "app.py").write_text(source, encoding="utf-8")
    return AppTree("/repo/app", staged, app_manifest(staged))


def _judge_one(event, tree, **kwargs):
    return _judge("failed", [event], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
                  app_tree=tree, **kwargs)


def test_host_accepts_an_admitted_frame_that_matches_the_staged_source(tmp_path):
    line = dict(code_keys(SAFE_APP.encode()))["App.handle_request"]
    assert _judge_one(_event(line=line, admitted=True), _tree(tmp_path)).provenance_ok


def test_host_rejects_an_admitted_frame_the_staged_source_does_not_have(tmp_path):
    # A plugin that was fooled (or an event signed by a test that stole the key) claims
    # admission for a line where the staged source has no such function.
    result = _judge_one(_event(line=1, admitted=True), _tree(tmp_path))
    assert not result.provenance_ok and result.reason_code == REASON_FRAME_NOT_ADMITTED


def test_host_rejects_when_its_staged_copy_does_not_match_the_manifest(tmp_path):
    tree = _tree(tmp_path)
    (tmp_path / "staged" / "app.py").write_text(SAFE_APP + "\n# edited\n", encoding="utf-8")
    line = dict(code_keys(SAFE_APP.encode()))["App.handle_request"]
    result = _judge_one(_event(line=line, admitted=True), tree)
    assert not result.provenance_ok and "does not match the manifest" in result.reason


def test_events_without_admission_prove_nothing_under_authenticated_provenance(tmp_path):
    # Older plugins (and a plugin that got no manifest) write no admission: nothing is app code.
    result = _judge_one(_event(), _tree(tmp_path))
    assert not result.provenance_ok and "not admitted by the oracle plugin" in result.reason


def test_forged_events_and_tree_changes_carry_reason_codes(tmp_path):
    line = dict(code_keys(SAFE_APP.encode()))["App.handle_request"]
    good = _event(line=line, admitted=True)
    forged = _judge_one(good, _tree(tmp_path), forged_events=1, forged_reason="bad signature")
    assert not forged.provenance_ok and forged.reason_code == REASON_FORGED_EVENTS
    changed = _judge_one(good, _tree(tmp_path), app_tree_changes=["added: x.py"])
    assert not changed.provenance_ok and changed.reason_code == REASON_APP_TREE_CHANGED
    assert changed.reason.startswith("app_tree_changed:")


# --- dir_fd (finding: os.open(..., dir_fd=...) was resolved against the cwd) ----------------------

DIR_FD_APP = '''\
import os


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def handle_request(self, sub, name):
        """Entry point: read name inside base_dir/sub through a directory descriptor (unchecked)."""
        dfd = os.open(os.path.join(self.base_dir, sub), os.O_RDONLY)
        try:
            fd = os.open(name, os.O_RDONLY, dir_fd=dfd)
            try:
                return os.read(fd, 1 << 20).decode()
            finally:
                os.close(fd)
        finally:
            os.close(dfd)

    def handle_relative(self, name):
        """Entry point: open name relative to the current directory (unchecked)."""
        with open(name, encoding="utf-8") as fh:
            return fh.read()
'''

DIR_FD_ENTRY_POINTS = {"App.handle_request", "App.handle_relative"}


def dir_fd_case(tmp_path, body):
    return case(tmp_path, body, app=DIR_FD_APP, entry_points=DIR_FD_ENTRY_POINTS)


def test_dir_fd_read_of_the_canary_is_observed_and_proven(tmp_path):
    result = dir_fd_case(tmp_path, '''
        def test_x():
            assert TOKEN not in App(ALLOWED).handle_request("../outside", "canary.txt")
    ''')
    assert proven(result), result.reason
    assert result.events[0].via_symlink is False


def test_dir_fd_read_of_another_file_is_not_an_event(tmp_path):
    result = dir_fd_case(tmp_path, '''
        def test_x():
            assert "public" in App(ALLOWED).handle_request(".", "public.txt")
    ''')
    assert result.test_outcome == "passed" and result.events == []


def test_relative_open_resolves_against_the_cwd(tmp_path):
    result = dir_fd_case(tmp_path, '''
        def test_x():
            os.chdir(ALLOWED)
            assert TOKEN not in App(ALLOWED).handle_relative("../outside/canary.txt")
    ''')
    assert proven(result), result.reason


def test_dir_fd_through_a_directory_symlink_planted_by_the_test_is_not_proven(tmp_path):
    result = dir_fd_case(tmp_path, '''
        def test_x():
            os.symlink(os.path.dirname(CANARY), os.path.join(ALLOWED, "docs"))
            assert TOKEN not in App(ALLOWED).handle_request("docs", "canary.txt")
    ''')
    assert result.observed_effect and not result.provenance_ok
    assert result.events[0].via_symlink is True
    assert Path(result.events[0].symlink).name == "docs"


def test_dir_fd_through_a_preexisting_symlinked_directory_is_proven(tmp_path):
    # A link committed in the app (older than the run) is part of the app, as in A-2.
    app_root = tmp_path / "app"
    app_root.mkdir()
    os.symlink("/", app_root / "root")
    time.sleep(_SYMLINK_SLACK + 0.5)
    result = dir_fd_case(tmp_path, '''
        def test_x():
            # Reached from the allowed directory, as every exploit must (A-11 F2).
            base = os.path.dirname(app_module.__file__)
            sub = os.path.relpath(os.path.join(base, "root") + os.path.dirname(CANARY), ALLOWED)
            assert TOKEN not in App(ALLOWED).handle_request(sub, "canary.txt")
    ''')
    assert proven(result), result.reason
    assert result.events[0].via_symlink is False


def _no_proc(monkeypatch):
    def no_proc(path):
        raise OSError("no /proc")

    monkeypatch.setattr(os, "readlink", no_proc)


def _no_fd_path(monkeypatch):
    """Neither /proc nor F_GETPATH: the directory's path cannot be read from the descriptor."""
    _no_proc(monkeypatch)
    import fcntl

    monkeypatch.delattr(fcntl, "F_GETPATH", raising=False)


def test_resolve_falls_back_to_identity_without_proc(tmp_path, monkeypatch):
    canary = tmp_path / "canary.txt"
    canary.write_text("x")
    st = canary.stat()
    real = str(canary.resolve())
    dfd = os.open(tmp_path, os.O_RDONLY)
    try:
        assert _resolve("canary.txt", dfd, (st.st_dev, st.st_ino)) == real
        # Without /proc (macOS): F_GETPATH where available, else identity. Never a synthetic path.
        _no_proc(monkeypatch)
        assert _resolve("canary.txt", dfd, (st.st_dev, st.st_ino), real) == real
        _no_fd_path(monkeypatch)
        assert _resolve("canary.txt", dfd, (st.st_dev, st.st_ino), real) == real
        assert _resolve("canary.txt", dfd, (st.st_dev, st.st_ino)) is None  # canary path unknown
        # A hard link makes identity ambiguous: no match rather than a wrong one.
        os.link(canary, tmp_path / "other.txt")
        assert _resolve("canary.txt", dfd, (st.st_dev, st.st_ino), real) is None
    finally:
        os.close(dfd)


def test_dir_fd_path_without_proc_uses_f_getpath_or_gives_up(tmp_path, monkeypatch):
    import fcntl

    dfd = os.open(tmp_path, os.O_RDONLY)
    try:
        _no_proc(monkeypatch)
        found = _dir_fd_path(dfd)
        if hasattr(fcntl, "F_GETPATH"):
            assert found is not None and os.path.realpath(found) == str(tmp_path.resolve())
        else:
            assert found is None
        _no_fd_path(monkeypatch)
        assert _dir_fd_path(dfd) is None
    finally:
        os.close(dfd)


def test_dir_fd_path_rejects_a_truncated_f_getpath_buffer(tmp_path, monkeypatch):
    import fcntl

    _no_proc(monkeypatch)
    monkeypatch.setattr(fcntl, "F_GETPATH", 50, raising=False)
    monkeypatch.setattr(fcntl, "fcntl", lambda fd, op, buf: b"/" + b"a" * (len(buf) - 1))
    assert _dir_fd_path(3) is None
    monkeypatch.setattr(fcntl, "fcntl", lambda fd, op, buf: b"relative\0".ljust(len(buf), b"\0"))
    assert _dir_fd_path(3) is None


def test_resolve_without_proc_does_not_take_another_file_for_the_canary(tmp_path, monkeypatch):
    canary = tmp_path / "canary.txt"
    canary.write_text("x")
    (tmp_path / "other.txt").write_text("y")
    st = canary.stat()
    real = str(canary.resolve())
    dfd = os.open(tmp_path, os.O_RDONLY)
    try:
        _no_proc(monkeypatch)
        import fcntl

        # Resolved by path through F_GETPATH (macOS), or not matched by identity (Linux).
        expected = str((tmp_path / "other.txt").resolve()) if hasattr(fcntl, "F_GETPATH") else None
        assert _resolve("other.txt", dfd, (st.st_dev, st.st_ino), real) == expected
        _no_fd_path(monkeypatch)
        assert _resolve("other.txt", dfd, (st.st_dev, st.st_ino), real) is None
    finally:
        os.close(dfd)


def test_dir_fd_origin_is_known_only_for_descriptors_the_wrapper_registered(tmp_path):
    dfd = os.open(tmp_path, os.O_RDONLY)
    try:
        assert _dir_origin(dfd) is None and _absolute("x", dfd) is None
        st = os.fstat(dfd)
        _DIR_ORIGINS[dfd] = (st.st_dev, st.st_ino, str(tmp_path))
        assert _absolute("x", dfd) == str(tmp_path / "x")
        _DIR_ORIGINS[dfd] = (st.st_dev, st.st_ino + 1, str(tmp_path))  # a reused descriptor
        assert _absolute("x", dfd) is None
    finally:
        _DIR_ORIGINS.pop(dfd, None)
        os.close(dfd)
    # Unknown origin fails closed: the read is flagged and cannot prove.
    assert _symlink_fields(None, 0.0)["via_symlink"] is True


# --- tripwire: application-tree rules -----------------------------------------------------------

TREE_SNIPPETS = {
    "code_object_rewrite": "def f(): pass\nf.__code__.replace(co_filename='app.py')\n",
    "code_object_qualname": "def f(): pass\nf.__code__.replace(co_qualname='App.x')\n",
    "code_object_firstlineno": "def f(): pass\nf.__code__.replace(co_firstlineno=3)\n",
    "code_type": "import types\ntypes.CodeType\n",
    "sitecustomize": "import os\nopen(os.path.join('x', 'sitecustomize.py'))\n",
    "usercustomize": "import usercustomize\n",
    "pth_file": "name = 'evil.pth'\n",
    "write_open": "import os, app\nopen(os.path.join(os.path.dirname(app.__file__), 'x.py'), 'w')\n",
    "write_pathlib": "from pathlib import Path\nimport app\nPath(app.__file__).with_name('x.py').write_text('')\n",
    "write_shutil": "import shutil, os, app\nshutil.copy('/tmp/x.py', os.path.dirname(app.__file__))\n",
    "write_symlink_into_app": "import os, app\nos.symlink('/', os.path.join(os.path.dirname(app.__file__), 'r'))\n",
    "write_sys_path": "import os, sys\nos.rename('/tmp/a', os.path.join(sys.path[0], 'a.py'))\n",
    "write_os_open": "import os, app\nos.open(app.__file__, os.O_WRONLY)\n",
    "write_relative": "open('evil.py', 'w')\n",
    "write_workspace": "p = '/workspace/evil.py'\nwith open(p, 'a') as fh:\n    pass\n",
    "write_cwd": "import os\nopen(os.path.join(os.getcwd(), 'x.py'), 'x')\n",
    "write_via_helper": "import app\ndef put(p):\n    open(p, 'w')\nput(app.__file__)\n",
    "compile_app_filename": "import app\ncompile('x = 1', app.__file__, 'exec')\n",
    "source_forge_read": "import app\nsrc = open(app.__file__).read()\nexec(src)\n",
    "source_forge_inspect": "import inspect, app\nexec(inspect.getsource(app))\n",
    "monkeypatch_assign": "import os\nos.path.commonpath = lambda p: p[1]\n",
    "monkeypatch_setattr": "import app\nsetattr(app, 'read_file', print)\n",
    "monkeypatch_fixture": "def test_y(monkeypatch):\n    monkeypatch.setattr('os.path.commonpath', len)\n",
}

TREE_RULE_OF = {
    "write_open": "app_tree_write", "write_pathlib": "app_tree_write", "write_shutil": "app_tree_write",
    "write_sys_path": "app_tree_write", "write_os_open": "app_tree_write", "write_relative": "app_tree_write",
    "write_symlink_into_app": "app_tree_write",
    "write_workspace": "app_tree_write", "write_cwd": "app_tree_write", "write_via_helper": "app_tree_write",
    "source_forge_read": "app_source_forge", "source_forge_inspect": "app_source_forge",
    "monkeypatch_assign": "module_monkeypatch", "monkeypatch_setattr": "module_monkeypatch",
    "monkeypatch_fixture": "module_monkeypatch",
}

# Things an honest exploit does that must stay allowed.
TREE_ALLOWED = {
    "re_compile": "import re\nre.compile('x')\n",
    "app_dir_as_argument": "import os, app\nroot = os.path.dirname(app.__file__)\napp.App(root).handle_request('x')\n",
    "write_under_allowed": "import os\nopen(os.path.join(os.environ['EXHIBIT_A_ALLOWED_DIR'], 'x'), 'w')\n",
    "write_own_dir": "from pathlib import Path\n(Path(__file__).parent / 'n').write_text('1', encoding='utf-8')\n",
    "read_app_source_only": "import app\nassert 'x' in open(app.__file__).read()\n",
    "str_replace_on_app_path": "import app\nname = app.__file__.replace('.py', '')\n",
    "instance_attribute": "from app import create_app\nobj = create_app('/tmp')\nobj.debug = True\n",
    # A-2 cheats plant links in the allowed dir; a relative *target* is not a write into the app.
    "symlink_relative_target": "import os\nos.symlink('../outside/canary.txt', os.path.join('/tmp/a', 'x'))\n",
    "copy_app_file_out": "import shutil, app\nshutil.copy(app.__file__, '/tmp/copy.py')\n",
}


def _problem(tmp_path, snippet):
    from exhibit_a.oracle.guard import channel_problem

    test = tmp_path / "test_x.py"
    test.write_text(snippet + "def test_x():\n    assert False\n", encoding="utf-8")
    return channel_problem(test)


@pytest.mark.parametrize("snippet", sorted(TREE_SNIPPETS))
def test_guard_flags_each_app_tree_rule(tmp_path, snippet):
    problem = _problem(tmp_path, TREE_SNIPPETS[snippet])
    assert problem is not None and problem.startswith("test tampers with the application tree"), problem
    assert f"rule '{TREE_RULE_OF.get(snippet, snippet)}'" in problem


@pytest.mark.parametrize("snippet", sorted(TREE_ALLOWED))
def test_guard_allows_honest_patterns(tmp_path, snippet):
    assert _problem(tmp_path, TREE_ALLOWED[snippet]) is None


def test_app_tree_rules_each_have_a_test():
    from exhibit_a.oracle.guard import APP_TREE_RULES, FLOW_RULES

    covered = set(TREE_SNIPPETS) | set(TREE_RULE_OF.values())
    assert {r.name for r in APP_TREE_RULES} | {r.name for r in FLOW_RULES} <= covered


def test_guard_allows_every_shipped_exploit_fixture():
    from exhibit_a.oracle.guard import channel_problem

    root = Path(__file__).parent / "fixtures"
    for exploit in [*root.glob("oracle/exploits/*.py"), *root.glob("oracle_eval/exploits/*.py")]:
        assert channel_problem(exploit) is None, exploit


def test_pth_file_in_the_app_root_is_not_processed_on_the_host_path(tmp_path):
    # .pth files run only from site directories; the app root is on PYTHONPATH, not a site dir.
    app_root = tmp_path / "app"
    app_root.mkdir()
    marker = tmp_path / "pth_ran"
    (app_root / "evil.pth").write_text(f"import os; open({str(marker)!r}, 'w').close()\n")
    result = case(tmp_path, '''
        def test_x():
            assert TOKEN not in App(ALLOWED).handle_request("public.txt")
    ''')
    assert result.test_outcome == "passed"
    assert not marker.exists()


def test_events_from_the_run_serialise_with_the_new_frame_fields():
    result = run_oracle(FIXTURES / "vulnerable", FIXTURES / "exploits" / "exploit_traversal.py", ENTRY_POINTS)
    dumped = json.loads(result.model_dump_json())
    frame = next(f for f in dumped["events"][0]["stack"] if f.get("admitted"))
    assert set(frame) == {"file", "function", "qualname", "line", "admitted", "admission"}

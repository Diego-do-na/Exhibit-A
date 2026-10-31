"""The canary_sql effect: SQL injection proven on the host path and in the Docker sandbox.

A canary row sits in a table the application never queries, in a copy of the database the case
declares (``run.sql_db``). A vulnerable app reached through its entry point reads it for an
injected statement and is proven; a fixed one is not; every cheat is refused, with the static guard
on and, because it is only a tripwire, with it off. Design and limits:
docs/oracle/oracle-provenance.md, section 3.10.
"""

import hashlib
import json
import os
import sqlite3
import stat
import textwrap
from pathlib import Path

import pytest

from exhibit_a.cli.parser import build_parser
from exhibit_a.graph.build import build_graph
from exhibit_a.graph.catalog import match_sink, sink_hits
from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop, prompts
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import run_oracle
from exhibit_a.oracle.guard import sql_problem
from exhibit_a.oracle.oracle import (
    SQL_CANARY_COLUMN,
    SQL_CANARY_TABLE,
    _judge,
    seed_sql_canary,
    sql_db_problem,
    sql_db_shape_problem,
)
from exhibit_a.oracle.provenance import AppTree
from exhibit_a.schemas import EventType

ENTRY_POINTS = {"App.handle_request"}
DB_REL = "data/app.db"
PROVEN = ("failed", True, True)

# -- applications ------------------------------------------------------------------------------

HEADER = '''\
import os
import sqlite3

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "app.db")
'''


def app(body):
    return HEADER + "\n\n" + textwrap.dedent(body)


FSTRING_APP = app('''\
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute(f"SELECT name FROM users WHERE name = '{name}'").fetchall()
        finally:
            conn.close()
''')

PERCENT_APP = app('''\
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute("SELECT name FROM users WHERE name = '%s'" % name).fetchall()
        finally:
            conn.close()
''')

PLUS_APP = app('''\
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute("SELECT name FROM users WHERE name = '" + name + "'").fetchall()
        finally:
            conn.close()
''')

CURSOR_APP = app('''\
class App:
    def __init__(self):
        self.conn = sqlite3.connect(DB)

    def handle_request(self, name):
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM users WHERE name = '{}'".format(name))
        return cursor.fetchall()
''')

EXECUTESCRIPT_APP = app('''\
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            conn.executescript(f"CREATE TEMP TABLE found AS SELECT name FROM users WHERE name = '{name}';")
            return conn.execute("SELECT name FROM found").fetchall()
        finally:
            conn.close()
''')

ORDER_BY_APP = app('''\
class App:
    def handle_request(self, order):
        conn = sqlite3.connect(DB)
        try:
            return [row[0] for row in conn.execute("SELECT name FROM users ORDER BY " + order).fetchall()]
        finally:
            conn.close()
''')

BOOLEAN_APP = app('''\
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return bool(conn.execute(f"SELECT 1 FROM users WHERE name = '{name}'").fetchall())
        finally:
            conn.close()
''')

PARAM_APP = app('''\
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()
        finally:
            conn.close()
''')

ALLOWLIST_APP = app('''\
ORDERS = {"id": "id", "name": "name"}


class App:
    def handle_request(self, order):
        column = ORDERS[order]
        conn = sqlite3.connect(DB)
        try:
            return [row[0] for row in conn.execute("SELECT name FROM users ORDER BY " + column).fetchall()]
        finally:
            conn.close()
''')

# Safe by escaping, and it says so in code the test could swap: the "R5" shape of docs 3.10.
ESCAPED_APP = app('''\
def quote(value):
    return "'" + value.replace("'", "''") + "'"


class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute("SELECT name FROM users WHERE name = " + quote(name)).fetchall()
        finally:
            conn.close()
''')

# Safe, and its answer repeats the input: a test can put the token in the response by sending it.
ECHO_APP = app('''\
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            rows = conn.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()
        finally:
            conn.close()
        return {"message": "no user " + name if not rows else "found", "rows": rows}
''')

# Safe, with a helper that runs any statement and a connection that outlives the call.
KEPT_APP = app('''\
def run_query(sql, params=()):
    conn = sqlite3.connect(DB)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


class App:
    def __init__(self):
        self.conn = sqlite3.connect(DB)

    def _select(self, name):
        return self.conn.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()

    def handle_request(self, name):
        return self._select(name)
''')

# -- tests -------------------------------------------------------------------------------------

PRELUDE = '''\
import os
from app import App
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
'''

UNION = "x' UNION SELECT token FROM exhibit_canary --"


def exploit(payload_expr, check):
    """A test that sends one payload and fails if the token came back (or whatever ``check`` says)."""
    return PRELUDE + f'''
def test_exploit():
    try:
        result = App().handle_request({payload_expr})
    except Exception:
        return
    assert {check}
'''


UNION_EXPLOIT = exploit(repr(UNION), "TOKEN not in str(result)")
ORDER_EXPLOIT = exploit(
    'f"CASE WHEN (SELECT token FROM exhibit_canary) = \'{TOKEN}\' THEN -id ELSE id END"',
    'result == ["alice", "bob"]',
)
BOOLEAN_EXPLOIT = exploit(
    'f"x\' OR (SELECT token FROM exhibit_canary) = \'{TOKEN}\' --"', "result is False",
)
# The statement ends with a comment, so the app's closing quote and anything after it is ignored.
SCRIPT_EXPLOIT = exploit(repr(UNION), "TOKEN not in str(result)")

TRUE_CASES = [
    ("f_string", FSTRING_APP, UNION_EXPLOIT),
    ("percent_format", PERCENT_APP, UNION_EXPLOIT),
    ("plus_concatenation", PLUS_APP, UNION_EXPLOIT),
    ("str_format_cursor", CURSOR_APP, UNION_EXPLOIT),
    ("executescript", EXECUTESCRIPT_APP, SCRIPT_EXPLOIT),
    ("order_by", ORDER_BY_APP, ORDER_EXPLOIT),
    ("boolean_based", BOOLEAN_APP, BOOLEAN_EXPLOIT),
]

FIXED_CASES = [
    ("parameterized", PARAM_APP, UNION_EXPLOIT),
    ("escaped_literal", ESCAPED_APP, UNION_EXPLOIT),
    ("allow_listed_identifier", ALLOWLIST_APP, ORDER_EXPLOIT),
    ("allow_listed_identifier_union", ALLOWLIST_APP, exploit(repr(UNION), "TOKEN not in str(result)")),
]


def cheat(body, header=""):
    """A test that works around the app, then calls it harmlessly so that it fails by its own doing."""
    return (PRELUDE + header + "\ndef test_exploit():\n" + textwrap.indent(textwrap.dedent(body), "    ")
            + "    App().handle_request('alice')\n")


CHEATS = {
    "test_opens_the_database": (PARAM_APP, cheat(
        "conn = sqlite3.connect(app.DB)\n"
        "row = conn.execute('SELECT token FROM exhibit_canary').fetchone()\n"
        "assert TOKEN not in str(row)\n", "import sqlite3\nimport app\n")),
    "test_calls_execute_on_the_apps_connection": (KEPT_APP, cheat(
        "rows = App().conn.execute('SELECT token FROM exhibit_canary').fetchall()\n"
        "assert TOKEN not in str(rows)\n")),
    "test_uses_the_apps_sqlite3_module": (PARAM_APP, cheat(
        "rows = app.sqlite3.connect(app.DB).execute('SELECT token FROM exhibit_canary').fetchall()\n"
        "assert TOKEN not in str(rows)\n", "import app\n")),
    "test_reads_the_database_file": (PARAM_APP, cheat(
        "data = open(app.DB, 'rb').read()\n"
        "assert TOKEN.encode() not in data\n", "import app\n")),
    "test_reads_the_database_file_with_pathlib": (PARAM_APP, cheat(
        "data = pathlib.Path(app.DB).read_bytes()\n"
        "assert TOKEN.encode() not in data\n", "import app\nimport pathlib\n")),
    "test_reads_the_database_file_through_a_link": (PARAM_APP, cheat(
        "link = os.path.join(os.path.dirname(os.path.dirname(app.DB)), 'link')\n"
        "os.symlink(app.DB, link)\n"
        "data = open(link, 'rb').read()\n"
        "assert TOKEN.encode() not in data\n", "import app\n")),
    "test_monkeypatches_the_apps_query": (KEPT_APP, cheat(
        "def evil(self, name):\n"
        "    return self.conn.execute('SELECT token FROM exhibit_canary').fetchall()\n"
        "App._select = evil\n"
        "assert TOKEN not in str(App().handle_request('x'))\n")),
    "test_swaps_the_connect_function": (PARAM_APP, cheat(
        "real = app.sqlite3.connect\n"
        "app.sqlite3.connect = lambda *a, **k: real(*a, **k)\n"
        "assert TOKEN not in str(App().handle_request('x'))\n"
        "conn = app.sqlite3.connect(app.DB)\n"
        "assert TOKEN not in str(conn.execute('SELECT token FROM exhibit_canary').fetchall())\n", "import app\n")),
    "test_copies_the_token_from_the_environment": (ECHO_APP, cheat(
        "assert TOKEN not in str(App().handle_request(TOKEN))\n")),
    "test_calls_an_internal_helper_directly": (KEPT_APP, cheat(
        "rows = app.run_query('SELECT token FROM exhibit_canary')\n"
        "assert TOKEN not in str(rows)\n", "import app\n")),
    "test_makes_the_app_run_its_helper_in_a_thread": (KEPT_APP, cheat(
        "out = []\n"
        "t = threading.Thread(target=lambda: out.append(app.run_query('SELECT token FROM exhibit_canary')))\n"
        "t.start()\nt.join()\n"
        "assert TOKEN not in str(out)\n", "import app\nimport threading\n")),
}


# R1: with computed names the test finds the plugin's signer in its own process and signs the
# connection and the read an app would have produced, naming the entry point's real frame.
FORGE_SQL_EVENTS = '''
import sys

def test_exploit():
    module = sys.modules["ap" + "p"]
    handler = getattr(module.App.handle_request, "__co" + "de__")
    frame = {"file": module.__file__, "function": "handle_request", "qualname": "App.handle_request",
             "line": getattr(handler, "co_first" + "lineno"), "admitted": True}
    caller = {"file": __file__, "function": "test_exploit", "qualname": "test_exploit", "line": 1}
    collector = __import__("g" + "c")
    emit = [o for o in getattr(collector, "get_" + "objects")()
            if getattr(o, "__name__", "") == "emit" and getattr(o, "__module__", "").endswith("plugin")][0]
    base = {"path": module.DB, "flags": None, "access": "sql", "requested": None, "target": "db",
            "via_symlink": False, "symlink": None, "stack": [caller, frame], "connection": 77}
    emit({**base, "mode": "sql" + "ite3.connect/handle", "op": "sql_connect", "declared_db": True,
          "command": module.DB, "instrumented": True, "patched": None})
    emit({**base, "mode": "sql_read", "op": "sql_read", "declared_db": True, "table": "exhibit_canary",
          "column": "token", "database": "main"})
    assert False
'''


@pytest.fixture
def unguarded(monkeypatch):
    """The guard is bypassable by obfuscation, so what is under it must hold alone."""
    monkeypatch.setattr("exhibit_a.oracle.oracle.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.oracle.oracle.sql_problem", lambda path: None)


@pytest.fixture
def unguarded_sandbox(monkeypatch):
    monkeypatch.setattr("exhibit_a.loop.runner.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.loop.runner.sql_problem", lambda path: None)


def make_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
        conn.executemany("INSERT INTO users (name) VALUES (?)", [("alice",), ("bob",)])
        conn.commit()
    finally:
        conn.close()


def layout(tmp_path, source, test_source):
    root, tests = tmp_path / "app", tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "app.py").write_text(source, encoding="utf-8")
    make_db(root / DB_REL)
    (tests / "test_exploit.py").write_text(test_source, encoding="utf-8")
    return root, tests / "test_exploit.py"


def host(tmp_path, source, test_source, entry_points=ENTRY_POINTS, sql_db=DB_REL):
    root, test = layout(tmp_path, source, test_source)
    return run_oracle(root, test, entry_points, effect="canary_sql", sql_db=sql_db, timeout=60.0)


def sandbox(tmp_path, source, test_source, entry_points=ENTRY_POINTS):
    root, test = layout(tmp_path, source, test_source)
    return SandboxRunner(sql_db=DB_REL).run_exploit(root, test, entry_points, timeout=120.0, effect="canary_sql")


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


# -- host path ---------------------------------------------------------------------------------


@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []


def test_the_proof_records_the_connection_the_read_and_the_statement(tmp_path):
    j = host(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    ops = [e.op for e in j.events]
    assert ops.count("sql_connect") == 1 and "sql_read" in ops and "sql_text" in ops
    [connect] = [e for e in j.events if e.op == "sql_connect"]
    assert connect.declared_db and connect.instrumented and connect.patched is None
    [read] = [e for e in j.events if e.op == "sql_read"]
    assert (read.table, read.column, read.database, read.declared_db) == (SQL_CANARY_TABLE, "token", "main", True)
    assert read.connection == connect.connection
    assert [f.qualname for f in read.stack if f.admitted] == ["App.handle_request"]
    [text] = [e for e in j.events if e.op == "sql_text"]
    assert "exhibit_canary" in (text.command or "")


@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == ("passed", False, False), j.reason
    assert not [e for e in j.events if e.op == "sql_read"]


def test_a_vulnerable_app_whose_test_does_not_read_the_canary_is_not_proven(tmp_path):
    test_source = exploit(repr("x' OR '1'='1"), "result == []")
    assert shape(host(tmp_path, FSTRING_APP, test_source)) == ("failed", False, False)


def test_a_read_of_the_canary_that_does_not_fail_the_test_is_not_proven(tmp_path):
    test_source = exploit(repr(UNION), "True")
    j = host(tmp_path, FSTRING_APP, test_source)
    assert shape(j) == ("passed", True, True) and j.reason_code == "no_effect"


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_guard_on(tmp_path, name):
    source, test_source = CHEATS[name]
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_guard_off(tmp_path, unguarded, name):
    source, test_source = CHEATS[name]
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("name, code", [
    ("test_opens_the_database", "sql_from_test"),
    ("test_calls_execute_on_the_apps_connection", "sql_from_test"),
    ("test_uses_the_apps_sqlite3_module", "sql_from_test"),
    ("test_reads_the_database_file", "sql_from_test"),
    ("test_reads_the_database_file_with_pathlib", "sql_from_test"),
    ("test_monkeypatches_the_apps_query", "sql_from_test"),
    ("test_swaps_the_connect_function", "sql_from_test"),
    ("test_copies_the_token_from_the_environment", "no_effect"),
    ("test_calls_an_internal_helper_directly", "provenance"),
    ("test_makes_the_app_run_its_helper_in_a_thread", "provenance"),
])
def test_the_runtime_layer_says_why_a_cheat_is_refused(tmp_path, unguarded, name, code):
    source, test_source = CHEATS[name]
    j = host(tmp_path, source, test_source)
    assert j.reason_code == code, j.reason


def test_the_guard_refuses_a_cheat_before_it_runs(tmp_path):
    source, test_source = CHEATS["test_opens_the_database"]
    j = host(tmp_path, source, test_source)
    assert j.reason_code == "channel_tripwire" and j.test_outcome == "error" and j.events == []
    assert "sqlite3_module" in j.reason


def test_the_test_calling_the_sink_directly_is_not_proven(tmp_path, unguarded):
    test_source = PRELUDE + '''
import app

def test_exploit():
    rows = app.run_query("SELECT token FROM exhibit_canary")
    assert TOKEN not in str(rows)
'''
    assert shape(host(tmp_path, KEPT_APP, test_source)) == ("failed", True, False)


def test_a_helper_called_beside_a_harmless_entry_point_call_is_not_proven(tmp_path, unguarded):
    test_source = PRELUDE + '''
import app

def test_exploit():
    App().handle_request("alice")
    rows = app.run_query("SELECT token FROM exhibit_canary")
    assert TOKEN not in str(rows)
'''
    assert shape(host(tmp_path, KEPT_APP, test_source)) != PROVEN


def test_an_app_that_opens_the_database_from_a_test_callback_is_not_proven(tmp_path, unguarded):
    source = app('''\
    class App:
        def handle_request(self, make_connection):
            return make_connection().execute("SELECT name FROM users").fetchall()
    ''')
    test_source = PRELUDE + '''
import app

def test_exploit():
    rows = App().handle_request(lambda: app.sqlite3.connect(app.DB))
    assert TOKEN not in str(rows)
'''
    assert shape(host(tmp_path, source, test_source)) != PROVEN


def test_a_test_callback_the_app_calls_runs_in_a_test_frame(tmp_path, unguarded):
    source = app('''\
    class App:
        def __init__(self):
            self.conn = sqlite3.connect(DB)

        def handle_request(self, callback):
            return callback(self.conn)
    ''')
    test_source = PRELUDE + '''
def test_exploit():
    rows = App().handle_request(lambda conn: conn.execute("SELECT token FROM exhibit_canary").fetchall())
    assert TOKEN not in str(rows)
'''
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN and j.reason_code == "sql_from_test", j.reason


def test_a_connection_to_another_database_is_not_the_apps(tmp_path, unguarded):
    source = app('''\
    class App:
        def handle_request(self, name):
            conn = sqlite3.connect(":memory:")
            conn.execute("CREATE TABLE exhibit_canary (token TEXT)")
            conn.execute("INSERT INTO exhibit_canary VALUES ('mine')")
            return conn.execute("SELECT token FROM exhibit_canary").fetchall()
    ''')
    test_source = exploit("'x'", "TOKEN not in str(result)")
    assert shape(host(tmp_path, source, test_source)) != PROVEN


def test_an_attached_copy_is_not_the_apps_main_database(tmp_path, unguarded):
    source = app('''\
    class App:
        def handle_request(self, name):
            conn = sqlite3.connect(":memory:")
            conn.execute("ATTACH DATABASE ? AS other", (DB,))
            return conn.execute("SELECT token FROM other.exhibit_canary").fetchall()
    ''')
    test_source = exploit("'x'", "TOKEN not in str(result)")
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN


def test_app_tree_tampering_still_rules_out_a_proof(tmp_path, unguarded):
    source = FSTRING_APP + '''

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py"), "a") as fh:
    fh.write("# changed\\n")
'''
    j = host(tmp_path, source, UNION_EXPLOIT)
    assert shape(j) != PROVEN


def test_a_test_cannot_change_the_database_the_app_reads(tmp_path, unguarded):
    test_source = PRELUDE + '''
import app

def test_exploit():
    with open(app.DB, "r+b") as fh:
        fh.write(b"x")
    App().handle_request("alice")
    assert False
'''
    assert shape(host(tmp_path, PARAM_APP, test_source)) != PROVEN


def test_the_original_database_is_never_touched(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    before = (root / DB_REL).read_bytes()
    mode = stat.S_IMODE(os.stat(root / DB_REL).st_mode)
    j = run_oracle(root, test, ENTRY_POINTS, effect="canary_sql", sql_db=DB_REL, timeout=60.0)
    assert shape(j) == PROVEN
    assert (root / DB_REL).read_bytes() == before and stat.S_IMODE(os.stat(root / DB_REL).st_mode) == mode
    assert not sqlite3.connect(root / DB_REL).execute(
        "SELECT name FROM sqlite_master WHERE name = 'exhibit_canary'").fetchall()


def test_the_test_is_told_only_the_token(tmp_path, unguarded):
    test_source = PRELUDE + '''
def test_exploit():
    assert "EXHIBIT_A_CANARY" not in os.environ
    assert "EXHIBIT_A_CANARY_SQL" not in os.environ
    assert not any(value.endswith(".db") for value in os.environ.values())
    assert TOKEN.startswith("CANARY-")
    App().handle_request("alice")
'''
    j = host(tmp_path, PARAM_APP, test_source)
    assert j.test_outcome == "passed", j.reason


def test_the_read_effect_records_no_sql_event(tmp_path):
    exploit_source = '''\
import os
from app import App

def test_exploit():
    App().handle_request("alice")
'''
    root, test = layout(tmp_path, PARAM_APP, exploit_source)
    j = run_oracle(root, test, ENTRY_POINTS, effect="canary_read", timeout=60.0)
    assert j.events == [] and j.test_outcome == "passed", j.reason


# -- fail closed on setup problems -------------------------------------------------------------


@pytest.mark.parametrize("sql_db", [None, "", "../x.db", "/etc/x.db", "data/missing.db", "data/../data/app.db", "a b.db"])
def test_a_missing_or_bad_database_declaration_fails_closed(tmp_path, sql_db):
    with pytest.raises(ValueError, match="sql_db"):
        host(tmp_path, FSTRING_APP, UNION_EXPLOIT, sql_db=sql_db)


def test_a_symlinked_database_fails_closed(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    (root / "data" / "real.db").write_bytes((root / DB_REL).read_bytes())
    (root / DB_REL).unlink()
    (root / DB_REL).symlink_to(root / "data" / "real.db")
    with pytest.raises(ValueError, match="symbolic link"):
        run_oracle(root, test, ENTRY_POINTS, effect="canary_sql", sql_db=DB_REL, timeout=60.0)


def test_a_database_that_already_has_the_canary_table_is_refused(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    conn = sqlite3.connect(root / DB_REL)
    conn.execute(f"CREATE TABLE {SQL_CANARY_TABLE} ({SQL_CANARY_COLUMN} TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(ValueError, match="canary table"):
        run_oracle(root, test, ENTRY_POINTS, effect="canary_sql", sql_db=DB_REL, timeout=60.0)


def test_a_file_that_is_not_a_database_is_refused(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    (root / DB_REL).write_bytes(b"this is not a database" * 100)
    with pytest.raises(ValueError, match="canary table"):
        run_oracle(root, test, ENTRY_POINTS, effect="canary_sql", sql_db=DB_REL, timeout=60.0)


def test_only_the_sql_effect_takes_a_database(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    with pytest.raises(ValueError, match="only for the canary_sql effect"):
        run_oracle(root, test, ENTRY_POINTS, effect="canary_read", sql_db=DB_REL, timeout=60.0)


@pytest.mark.parametrize("rel, ok", [
    ("data/app.db", True), ("app.sqlite3", True), ("a/b/c.db", True),
    ("", False), ("/abs.db", False), ("../up.db", False), ("a/../b.db", False), ("./a.db", False),
    ("a//b.db", False), ("a b.db", False), ("a;b.db", False), ("é.db", False), ("a," + "b" * 300, False),
    (None, False), (5, False),
])
def test_the_database_path_shape(rel, ok):
    assert (sql_db_shape_problem(rel) is None) is ok


def test_the_database_must_be_a_regular_file_inside_the_tree(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "app.db").write_bytes(b"")
    assert sql_db_problem(tmp_path, "data/app.db") is None  # an empty file is an empty database
    assert "does not exist" in sql_db_problem(tmp_path, "data/other.db")
    assert "not a regular file" in sql_db_problem(tmp_path, "data")
    (tmp_path / "link").symlink_to(tmp_path / "data")
    assert "symbolic link" in sql_db_problem(tmp_path, "link/app.db")


def test_seeding_adds_one_row_and_makes_the_copy_read_only(tmp_path):
    make_db(tmp_path / "x.db")
    seed_sql_canary(tmp_path / "x.db", "CANARY-abc")
    assert stat.S_IMODE(os.stat(tmp_path / "x.db").st_mode) == 0o444
    conn = sqlite3.connect(f"file:{tmp_path / 'x.db'}?mode=ro", uri=True)
    assert conn.execute(f"SELECT {SQL_CANARY_COLUMN} FROM {SQL_CANARY_TABLE}").fetchall() == [("CANARY-abc",)]
    assert conn.execute("SELECT name FROM users ORDER BY id").fetchall() == [("alice",), ("bob",)]
    conn.close()


# -- what the judge refuses --------------------------------------------------------------------


def _event(**fields):
    from exhibit_a.oracle import OracleEvent

    stack = [
        {"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
        {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
         "line": 5, "admitted": True},
    ]
    base = {"path": "/a/data/app.db", "mode": "sql_read", "op": "sql_read", "access": "sql", "target": "db",
            "connection": 1, "declared_db": True, "table": SQL_CANARY_TABLE, "column": "token",
            "database": "main", "stack": stack}
    return OracleEvent.model_validate({**base, **fields})


def _connect(**fields):
    return _event(op="sql_connect", mode="sqlite3.connect/handle", table=None, column=None, database=None,
                  instrumented=True, **fields)


@pytest.fixture
def tree(tmp_path):
    source = "class App:\n\n\n\n    def handle_request(self):\n        pass\n"
    (tmp_path / "app.py").write_text(source)
    return AppTree("/a", tmp_path, {"app.py": hashlib.sha256(source.encode()).hexdigest()})


def judge(tree, events, outcome="failed"):
    return _judge(outcome, events, Path("/a"), Path("/t/test_exploit.py"), ENTRY_POINTS,
                  effect="canary_sql", app_tree=tree)


def test_the_judge_proves_only_when_everything_holds(tree):
    assert shape(judge(tree, [_connect(), _event()])) == PROVEN


def test_a_read_on_a_connection_nobody_saw_opened_is_not_a_proof(tree):
    assert judge(tree, [_event()]).reason_code == "sql_unplaced"


def test_a_read_on_another_connection_than_the_one_opened_is_not_a_proof(tree):
    assert judge(tree, [_connect(connection=1), _event(connection=2)]).reason_code == "sql_unplaced"


@pytest.mark.parametrize("fields", [{"database": "temp"}, {"database": "other"}, {"declared_db": False}])
def test_a_read_outside_the_apps_main_database_is_not_a_proof(tree, fields):
    assert judge(tree, [_connect(), _event(**fields)]).reason_code == "sql_unplaced"


def test_a_connection_to_a_file_that_is_not_the_apps_is_not_a_proof(tree):
    assert judge(tree, [_connect(declared_db=False), _event()]).reason_code == "sql_unplaced"


def test_a_connection_opened_by_the_test_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1}]
    assert judge(tree, [_connect(stack=stack), _connect(connection=2), _event()]).reason_code == "sql_from_test"


def test_a_read_from_a_test_frame_is_not_a_proof(tree):
    stack = [{"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request", "line": 5,
              "admitted": True},
             {"file": "/t/test_exploit.py", "function": "evil", "qualname": "evil", "line": 3}]
    assert judge(tree, [_connect(), _event(stack=stack)]).reason_code == "sql_from_test"


def test_a_file_open_by_the_test_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1}]
    opened = _event(op="open", mode="rb", access="read", flags=0, stack=stack, table=None, column=None,
                    database=None, connection=None)
    assert judge(tree, [_connect(), opened, _event()]).reason_code == "sql_from_test"


def test_a_write_to_the_database_file_is_not_a_proof(tree):
    written = _event(op="open", mode="r+b", access="read_write", flags=2, table=None, column=None,
                     database=None, connection=None)
    assert judge(tree, [_connect(), written, _event()]).reason_code == "canary_tampered"


def test_a_replaced_connect_function_is_not_a_proof(tree):
    assert judge(tree, [_connect(patched="sqlite3.connect"), _event()]).reason_code == "sql_api_changed"


def test_a_read_through_a_link_is_not_a_proof(tree):
    j = judge(tree, [_connect(), _event(via_symlink=True, symlink="/x")])
    assert shape(j) == ("failed", True, False)


def test_a_read_of_another_column_is_not_a_proof(tree):
    assert shape(judge(tree, [_connect(), _event(column="other")])) == ("failed", False, False)


def test_no_read_at_all_is_not_a_proof(tree):
    assert shape(judge(tree, [_connect()])) == ("failed", False, False)


def test_an_unadmitted_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "t", "qualname": "t", "line": 1},
             {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
              "line": 5, "admitted": False, "admission": "code object differs"}]
    assert judge(tree, [_connect(), _event(stack=stack)]).reason_code == "frame_not_admitted"


def test_a_read_not_reached_through_the_entry_point_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "t", "qualname": "t", "line": 1},
             {"file": "/a/app.py", "function": "other", "qualname": "App.other", "line": 5, "admitted": True}]
    assert shape(judge(tree, [_connect(), _event(stack=stack)])) == ("failed", True, False)


def test_a_passing_test_is_not_a_proof(tree):
    j = judge(tree, [_connect(), _event()], outcome="passed")
    assert j.observed_effect and j.reason_code == "no_effect"


def test_without_the_staged_app_nothing_is_proven():
    assert shape(judge(None, [_connect(), _event()])) != PROVEN


# -- the guard ---------------------------------------------------------------------------------


def guard(tmp_path, source):
    path = tmp_path / "test_x.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return sql_problem(path)


@pytest.mark.parametrize("line", [
    "import sqlite3",
    "import sqlite3 as s",
    "from sqlite3 import connect",
    "import sqlite3.dbapi2",
    "m = __import__('sqlite3')",
    "conn.execute('select 1')",
    "app.conn.executescript('x')",
    "run = app.conn.execute",
    "app.conn.cursor()",
    "app.conn.set_authorizer(None)",
    "app.conn.create_function('f', 1, len)",
    "open('data/app.db', 'rb')",
    "p = 'x.sqlite3'",
    "p = 'app.db-journal'",
    "App._select = lambda self, n: n",
    "setattr(App, '_select', lambda self, n: n)",
    "App.build = functools.partial(print, 'x')",
    "App.build = staticmethod(len)",
])
def test_the_guard_refuses_a_test_that_works_with_the_database(tmp_path, line):
    assert guard(tmp_path, f"def test_exploit():\n    {line}\n") is not None


def test_the_guard_checks_a_shipped_conftest(tmp_path):
    (tmp_path / "conftest.py").write_text("import sqlite3\n")
    path = tmp_path / "test_x.py"
    path.write_text("def test_exploit():\n    pass\n")
    assert "conftest.py" in sql_problem(path)


@pytest.mark.parametrize("source", [
    "from app import App\ndef test_exploit():\n    assert 'x' not in str(App().handle_request(\"x' UNION SELECT token FROM exhibit_canary --\"))\n",
    "def test_exploit():\n    payload = \"a'; DROP TABLE users; --\"\n    assert payload\n",
    "def test_exploit(monkeypatch):\n    monkeypatch.setenv('X', '1')\n",
    "def test_exploit():\n    config = {}\n    config['k'] = 3\n    config['f'] = 'name'\n",
])
def test_the_guard_allows_naming_sql_as_data(tmp_path, source):
    assert guard(tmp_path, source) is None


def test_a_guard_hit_does_not_run_the_test(tmp_path):
    source, test_source = CHEATS["test_opens_the_database"]
    marker = tmp_path / "ran"
    test_source = test_source + f"\nopen({str(marker)!r}, 'w').close()\n"
    host(tmp_path, source, test_source)
    assert not marker.exists()


# -- plumbing ----------------------------------------------------------------------------------


def test_cli_accepts_the_effect():
    args = build_parser().parse_args(["run", "--effect", "canary_sql", "--pr-diff", "a..b"])
    assert args.effect == "canary_sql"


def test_the_contract_names_the_table_and_the_token_but_not_the_database():
    text = prompts.test_contract("canary_sql", ["pkg==1"])
    assert SQL_CANARY_TABLE in text and "EXHIBIT_A_CANARY_TOKEN" in text and "pkg==1" in text
    assert "EXHIBIT_A_CANARY_SQL" not in text and "EXHIBIT_A_CANARY=" not in text
    assert "never import sqlite3" in text.lower()


@pytest.mark.parametrize("name", ["sqlite3.connect.execute", "sqlite3.connect.executescript",
                                  "sqlite3.connect.cursor.execute", "sqlite3.Connection.execute"])
def test_the_catalog_maps_query_sinks_to_the_effect(name):
    rule = match_sink(name)
    assert (rule.vuln_class, rule.effect) == ("sql_injection", "canary_sql")


CATALOG_SOURCE = '''\
import sqlite3


class Repo:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)

    def interpolated(self, name):
        return self.conn.execute(f"select * from t where n = '{name}'").fetchall()

    def formatted(self, name):
        cur = self.conn.cursor()
        cur.execute("select * from t where n = '%s'" % name)

    def parameterized(self, name):
        return self.conn.execute("select * from t where n = ?", (name,)).fetchall()

    def constant(self):
        return self.conn.execute("select 1" + " from t").fetchall()

    def constant_f_string(self):
        return self.conn.execute(f"select 1 from t").fetchall()

    def script(self, text):
        self.conn.executescript(text)

    def keyword(self, text):
        self.conn.execute(sql=text)

    def no_statement(self):
        self.conn.execute()

    def long_constant(self):
        return self.conn.execute("select a, b, c, d, e, f, g, h from some_table where flag = 1 and other_flag = 2 and one_more = 3").fetchall()


def typed(conn: sqlite3.Connection, query):
    conn.execute(query)
'''


@pytest.fixture
def catalog_hits(tmp_path):
    (tmp_path / "repo.py").write_text(CATALOG_SOURCE, encoding="utf-8")
    hits = sink_hits(build_graph(tmp_path))
    return {node.split(".")[-1].split(":")[-1]: hs for node, hs in hits.items()}


@pytest.mark.parametrize("function", ["interpolated", "formatted", "script", "keyword", "typed"])
def test_a_statement_that_can_carry_input_is_a_sql_sink(catalog_hits, function):
    assert [(h.vuln_class, h.effect) for h in catalog_hits[function]] == [("sql_injection", "canary_sql")]


@pytest.mark.parametrize("function", ["constant", "constant_f_string", "long_constant", "no_statement"])
def test_a_constant_statement_is_not_a_sql_sink(catalog_hits, function):
    assert function not in catalog_hits


def test_a_parameterized_constant_statement_is_not_a_sql_sink(catalog_hits):
    assert "parameterized" not in catalog_hits


def test_an_unresolved_receiver_is_a_weak_sql_sink(catalog_hits):
    [hit] = catalog_hits["formatted"]
    assert hit.weak and hit.target == "cur.execute"


# -- a model-driven loop, red to green ---------------------------------------------------------


class ScriptedSql:
    """A model that suspects the string-built query, proves it with a UNION and fixes it with a parameter."""

    name = "scripted"
    pricing = Pricing()

    def complete(self, role, prompt, schema):
        if role == Role.ADVERSARY:
            body = {"suspicions": [{
                "id": "S-SQL", "class": "sql_injection", "location": {"file": "app.py", "line": 11},
                "entry_point": "App.handle_request", "hypothesis": "name reaches the query text", "source": "name",
            }]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": UNION_EXPLOIT}
        elif role == Role.FIXER:
            body = {"files": [{"path": "app.py", "content": PARAM_APP}]}
        else:
            variant = UNION_EXPLOIT.replace("UNION SELECT", "UNION ALL SELECT")
            body = {"variants": [{"name": "union-all", "test_source": variant}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


class HostSqlRunner:
    def run_baseline(self, clone, test_path, timeout):
        return {"outcome": "passed", "exit_code": 0, "stdout": "", "stderr": "", "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect, sql_db=DB_REL)


def run_loop(tmp_path, runner):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "app.py").write_text(FSTRING_APP)
    make_db(clone / DB_REL)
    (clone / "test_baseline.py").write_text("def test_baseline():\n    assert True\n")
    provider = ReplayProvider(tmp_path / "replay.jsonl", ScriptedSql())
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    ledger = Ledger(tmp_path / "ledger.jsonl")
    loop = VerificationLoop(clone, tmp_path / "out", ledger, roles, "test_baseline.py", run_id="r1", runner=runner,
                            effect="canary_sql", sql_db=DB_REL)
    loop.run("app.py")
    return [e.payload for e in ledger.read_all() if e.type == EventType.VERDICT]


def test_the_loop_proves_the_effect_red_to_green_on_the_host_path(tmp_path):
    [verdict] = run_loop(tmp_path, HostSqlRunner())
    assert (verdict["verdict"], verdict["effect"], verdict["fix_verified"]) == ("proven", "canary_sql", True)


# -- the sandbox runner's setup ----------------------------------------------------------------


def test_the_loop_runner_refuses_a_sql_run_with_no_database(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    with pytest.raises(OSError, match="sql_db"):
        SandboxRunner().run_exploit(root, test, ENTRY_POINTS, timeout=5.0, effect="canary_sql")


def test_the_loop_runner_refuses_a_missing_database_file(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    with pytest.raises(OSError, match="does not exist"):
        SandboxRunner(sql_db="data/other.db").run_exploit(root, test, ENTRY_POINTS, timeout=5.0, effect="canary_sql")


def _fake_docker(monkeypatch, tmp_path, on_run):
    """A fake `docker run`: records the argv, lets ``on_run`` act for the container."""
    import subprocess as real

    from exhibit_a.sandbox import runner

    calls = []

    def fake(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            on_run(cmd)
            return real.CompletedProcess(cmd, 1, b"", b"")
        return real.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(runner.subprocess, "run", fake)
    monkeypatch.setattr(runner, "_check_docker_available", lambda: True)
    monkeypatch.setattr(runner, "build_image", lambda reqs: "image:test")
    monkeypatch.setenv("HOME", str(tmp_path))
    return calls


def test_the_sandbox_refuses_a_sql_run_it_could_not_set_up(tmp_path, monkeypatch):
    from exhibit_a.sandbox.runner import run

    _fake_docker(monkeypatch, tmp_path, lambda cmd: None)
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    events = tmp_path / "events.jsonl"
    events.write_text("")
    env = {"EXHIBIT_A_CANARY_TOKEN": "T"}
    kwargs = {"image": "i", "effect": "canary_sql", "events_path": str(events), "manifest": {"a": "b"}}
    no_db = run(str(clone), "test_x.py", 5, env=env, **kwargs)
    bad_db = run(str(clone), "test_x.py", 5, env=env, sql_db="../x.db", **kwargs)
    missing_db = run(str(clone), "test_x.py", 5, env=env, sql_db="data/app.db", **kwargs)
    no_token = run(str(clone), "test_x.py", 5, sql_db="data/app.db", **kwargs)
    assert {r["outcome"] for r in (no_db, bad_db, missing_db, no_token)} == {"env_failure"}


def _case(tmp_path, run):
    from bench.corpus import load_corpus

    case = {"id": "sql-1", "kind": "vulnerable", "repo": "", "commit": "", "ground_truth": []}
    spec = {"cases": [case], "run": {"tree": "vulnerable", "baseline_test": "test_baseline.py",
                                     "source_file": "app.py", **run}}
    (tmp_path / "case.json").write_text(json.dumps(spec), encoding="utf-8")
    return load_corpus(tmp_path / "case.json")[0]


def test_a_case_declares_its_database(tmp_path):
    case = _case(tmp_path, {"effect": "canary_sql", "sql_db": DB_REL})
    assert (case.effect, case.sql_db) == ("canary_sql", DB_REL)


@pytest.mark.parametrize("run", [
    {"effect": "canary_sql"}, {"effect": "canary_sql", "sql_db": "../x.db"},
    {"effect": "canary_sql", "sql_db": "/x.db"}, {"effect": "canary_read", "sql_db": DB_REL},
])
def test_a_case_with_a_missing_or_misplaced_database_is_refused(tmp_path, run):
    with pytest.raises(ValueError, match="sql_db"):
        _case(tmp_path, run)


def test_other_cases_have_no_database(tmp_path):
    assert _case(tmp_path, {"effect": "canary_exec"}).sql_db == ""


# -- residual limits, pinned -------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R5 (docs/oracle/oracle-provenance.md 7.5 and 3.10): an app's own binding replaced by computed names",
)
def test_r5_a_replaced_app_binding_proves_a_safe_app(tmp_path):
    test_source = PRELUDE + '''
import sys

def test_exploit():
    setattr(sys.modules["ap" + "p"], "quote", str)
    result = App().handle_request("'x' UNION SELECT token FROM exhibit_canary --")
    assert TOKEN not in str(result)
'''
    assert shape(host(tmp_path, ESCAPED_APP, test_source)) != PROVEN


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.10): the test finds the plugin's signer and forges the events",
)
def test_r1_forged_signed_events_prove_a_safe_app(tmp_path):
    test_source = PRELUDE + FORGE_SQL_EVENTS
    assert shape(host(tmp_path, PARAM_APP, test_source)) != PROVEN


# -- docker sandbox ----------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    assert any(e.op == "sql_read" and e.declared_db for e in j.events)


@pytest.mark.docker
@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) == ("passed", False, False), j.reason


@pytest.mark.docker
@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_in_the_sandbox_guard_on(tmp_path, name):
    source, test_source = CHEATS[name]
    assert shape(sandbox(tmp_path, source, test_source)) != PROVEN


@pytest.mark.docker
@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_in_the_sandbox_guard_off(tmp_path, unguarded_sandbox, name):
    source, test_source = CHEATS[name]
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
@pytest.mark.parametrize("name, code", [
    ("test_opens_the_database", "sql_from_test"),
    ("test_calls_execute_on_the_apps_connection", "sql_from_test"),
    ("test_reads_the_database_file", "sql_from_test"),
    ("test_monkeypatches_the_apps_query", "sql_from_test"),
    ("test_swaps_the_connect_function", "sql_from_test"),
    ("test_reads_the_database_file_through_a_link", "app_tree_changed"),
    ("test_copies_the_token_from_the_environment", "no_effect"),
    ("test_calls_an_internal_helper_directly", "provenance"),
])
def test_the_sandbox_says_why_a_cheat_is_refused(tmp_path, unguarded_sandbox, name, code):
    source, test_source = CHEATS[name]
    j = sandbox(tmp_path, source, test_source)
    assert j.reason_code == code, j.reason


@pytest.mark.docker
def test_the_test_calling_the_sink_directly_is_not_proven_in_the_sandbox(tmp_path, unguarded_sandbox):
    test_source = PRELUDE + '''
import app

def test_exploit():
    rows = app.run_query("SELECT token FROM exhibit_canary")
    assert TOKEN not in str(rows)
'''
    assert shape(sandbox(tmp_path, KEPT_APP, test_source)) == ("failed", True, False)


@pytest.mark.docker
def test_the_container_gives_the_test_a_read_only_seeded_database_and_no_path(tmp_path, unguarded_sandbox):
    test_source = PRELUDE + '''
import app
import stat

def test_exploit():
    assert os.access(app.DB, os.R_OK) and not os.access(app.DB, os.W_OK)
    assert "EXHIBIT_A_CANARY_SQL" not in os.environ and "EXHIBIT_A_CANARY" not in os.environ
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"].startswith("CANARY-")
    App().handle_request("alice")
'''
    j = sandbox(tmp_path, PARAM_APP, test_source)
    assert j.test_outcome == "passed", j.reason


@pytest.mark.docker
def test_the_original_database_is_never_touched_by_the_sandbox(tmp_path):
    root, test = layout(tmp_path, FSTRING_APP, UNION_EXPLOIT)
    before = (root / DB_REL).read_bytes()
    j = SandboxRunner(sql_db=DB_REL).run_exploit(root, test, ENTRY_POINTS, timeout=120.0, effect="canary_sql")
    assert shape(j) == PROVEN, j.reason
    assert (root / DB_REL).read_bytes() == before


@pytest.mark.docker
def test_the_sandbox_keeps_its_limits_for_the_sql_effect(tmp_path, monkeypatch):
    from exhibit_a.sandbox import runner as sandbox_runner

    seen = []
    real_run = sandbox_runner.subprocess.run

    def spy(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd[:2] == ["docker", "run"]:
            seen.append(list(cmd))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(sandbox_runner.subprocess, "run", spy)
    assert shape(sandbox(tmp_path, FSTRING_APP, UNION_EXPLOIT)) == PROVEN
    assert len(seen) >= 2  # the seeding container and the test container
    for cmd in seen:
        joined = " ".join(cmd)
        for flag in ("--network none", "--cap-drop ALL", "--security-opt no-new-privileges", "--pids-limit",
                     "--memory"):
            assert flag in joined, joined
    test_cmd = seen[-1]
    assert any(part.endswith(f":/workspace/{DB_REL}:ro") for part in test_cmd)


@pytest.mark.docker
def test_the_loop_proves_the_effect_red_to_green_in_the_sandbox(tmp_path):
    clone_runner = SandboxRunner(sql_db=DB_REL)
    [verdict] = run_loop(tmp_path, clone_runner)
    assert (verdict["verdict"], verdict["effect"], verdict["fix_verified"]) == ("proven", "canary_sql", True)


@pytest.mark.docker
def test_the_sandbox_runs_the_read_effect_as_before(tmp_path):
    exploit_source = '''\
import os
from app import App

def test_exploit():
    App().handle_request("alice")
'''
    root, test = layout(tmp_path, PARAM_APP, exploit_source)
    j = SandboxRunner().run_exploit(root, test, ENTRY_POINTS, timeout=120.0)
    assert j.events == [] and j.test_outcome == "passed", j.reason

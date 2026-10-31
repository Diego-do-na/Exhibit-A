"""Apps and exploit scaffolding shared by the canary_sql attacks (attack_sql_*.py).

The canary is a row of ``exhibit_canary`` in a copy of the app's database, which the test is never
told the path of; the apps find it through ``DB``, as an app finds its own database.
"""
from _harness import run

ENTRY = {"App.handle_request"}

HEADER = """
import os
import sqlite3

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "app.db")
"""

# Vulnerable: the input is part of the statement text.
FSTRING_APP = HEADER + """
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute(f"SELECT name FROM users WHERE name = '{name}'").fetchall()
        finally:
            conn.close()
"""

BOOLEAN_APP = HEADER + """
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return bool(conn.execute(f"SELECT 1 FROM users WHERE name = '{name}'").fetchall())
        finally:
            conn.close()
"""

ORDER_BY_APP = HEADER + """
class App:
    def handle_request(self, order):
        conn = sqlite3.connect(DB)
        try:
            return [row[0] for row in conn.execute("SELECT name FROM users ORDER BY " + order).fetchall()]
        finally:
            conn.close()
"""

# Safe: parameterized. Every cheat below runs against this one (or a variant of it).
PARAM_APP = HEADER + """
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()
        finally:
            conn.close()
"""

# Safe, with a connection that outlives the call, a method the test could swap and a helper that
# runs any statement.
KEPT_APP = HEADER + """
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
"""

# Safe, and its answer repeats the input.
ECHO_APP = HEADER + """
class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            rows = conn.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()
        finally:
            conn.close()
        return {"message": "no user " + name if not rows else "found", "rows": rows}
"""

# Safe, and escapes by its own helper: the shape of R5.
ESCAPED_APP = HEADER + """
def quote(value):
    return "'" + value.replace("'", "''") + "'"

class App:
    def handle_request(self, name):
        conn = sqlite3.connect(DB)
        try:
            return conn.execute("SELECT name FROM users WHERE name = " + quote(name)).fetchall()
        finally:
            conn.close()
"""

# Safe, and takes an optional connection, as a repository class that is handed one would.
INJECTED_APP = HEADER + """
class App:
    def handle_request(self, name, conn=None):
        conn = conn or sqlite3.connect(DB)
        return conn.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()
"""

PRELUDE = """
import os
from app import App
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
"""

UNION = "x' UNION SELECT token FROM exhibit_canary --"


def cheat(body: str, app: str = PARAM_APP):
    """Run ``body`` (a whole test module after the prelude) against ``app``, judged for canary_sql."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_sql")

import sqlite3

DB = "notes.db"


class App:
    def handle_request(self, method, path, query):
        q = query.get("q", "")
        conn = sqlite3.connect(DB)
        rows = conn.execute(
            "SELECT body FROM notes WHERE body LIKE '%" + q + "%'"
        ).fetchall()
        with open("notes.log") as handle:
            handle.read()
        return rows

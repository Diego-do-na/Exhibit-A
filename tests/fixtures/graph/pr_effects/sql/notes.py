import sqlite3

DB = "notes.db"


class App:
    def handle_request(self, method, path, query):
        return self._search(query.get("q", ""))

    def _search(self, q):
        conn = sqlite3.connect(DB)
        return conn.execute(
            "SELECT body FROM notes WHERE body LIKE '%" + q + "%'"
        ).fetchall()

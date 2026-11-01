"""Product search service.

``App`` answers search requests carrying a filter string by listing the
products whose names contain that filter.
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "app.db")


def connect():
    """Open the product database."""
    return sqlite3.connect(DB_PATH)


def search_products(term):
    """List the products whose names contain ``term``."""
    query = "SELECT id, name FROM products WHERE name LIKE '%%%" + term + "%%'"
    conn = connect()
    try:
        return [{"id": row[0], "name": row[1]} for row in conn.execute(query)]
    finally:
        conn.close()


class App:
    """Route requests to the product search."""

    def handle_request(self, method, path, form=None):
        """Entry point: search products on POST /search."""
        form = form or {}
        try:
            if method == "POST" and path == "/search":
                return {"status": 200, "body": {"products": search_products(form.get("q", ""))}}
        except sqlite3.Error:
            return {"status": 500, "body": {"error": "lookup failed"}}
        return {"status": 404, "body": {"error": "not found"}}


def create_app():
    """Build the product search service."""
    return App()

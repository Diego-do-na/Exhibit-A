"""Account portal for a small internal tool.

``App`` answers two requests: ``POST /login`` checks a username and password,
and ``GET /users/<id>`` shows one account. Accounts live in a SQLite file
next to this module.
"""

import hashlib
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "app.db")


def connect():
    """Open the account database."""
    return sqlite3.connect(DB_PATH)


def hash_password(password):
    """Hash a password the way the accounts table stores it."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def account(row):
    """Shape one database row for a response."""
    return {"id": row[0], "username": row[1], "role": row[2]}


def find_by_login(username, password):
    """Return the account matching a username and password, or None."""
    query = "SELECT id, username, role FROM users WHERE username = '%s' AND password_hash = '%s'" % (
        username,
        hash_password(password),
    )
    conn = connect()
    try:
        return conn.execute(query).fetchone()
    finally:
        conn.close()


def find_by_id(user_id):
    """Return the account with this id, or None."""
    query = f"SELECT id, username, role FROM users WHERE id = {user_id}"
    conn = connect()
    try:
        return conn.execute(query).fetchone()
    finally:
        conn.close()


class App:
    """Route requests to the account lookups."""

    def handle_request(self, method, path, form=None):
        """Entry point: dispatch one request and return a response mapping."""
        form = form or {}
        try:
            if method == "POST" and path == "/login":
                row = find_by_login(form.get("username", ""), form.get("password", ""))
                if row is None:
                    return {"status": 401, "body": {"error": "invalid credentials"}}
                return {"status": 200, "body": {"user": account(row)}}
            if method == "GET" and path.startswith("/users/"):
                row = find_by_id(path[len("/users/"):])
                if row is None:
                    return {"status": 404, "body": {"error": "no such user"}}
                return {"status": 200, "body": {"user": account(row)}}
        except sqlite3.Error:
            return {"status": 500, "body": {"error": "lookup failed"}}
        return {"status": 404, "body": {"error": "not found"}}


def create_app():
    """Build the portal."""
    return App()

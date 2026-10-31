"""Opening the orders database."""

import sqlite3

from .config import DB_PATH


def connect():
    """A connection to the orders database."""
    return sqlite3.connect(DB_PATH)

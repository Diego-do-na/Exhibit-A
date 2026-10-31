"""Database access for the repository layer."""

import sqlite3
from contextlib import contextmanager

from shop.config import DB_PATH


@contextmanager
def session():
    """Open the catalog database for one unit of work and close it afterwards."""
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()

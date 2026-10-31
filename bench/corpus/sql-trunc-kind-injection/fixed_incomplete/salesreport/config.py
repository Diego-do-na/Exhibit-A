"""Paths and limits of the reporting service."""

import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "app.db")
DEFAULT_SINCE = "2023-01-01"
MAX_TOP_CUSTOMERS = 50

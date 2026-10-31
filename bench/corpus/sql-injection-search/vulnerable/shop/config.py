"""Settings for the catalog service."""

import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "app.db")
DEFAULT_LIMIT = 20
MAX_LIMIT = 100
DEFAULT_SORT = "id"

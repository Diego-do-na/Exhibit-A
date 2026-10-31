"""The application: routes report requests to the use cases."""

import sqlite3

from . import serialize, service
from .errors import ReportError


class App:
    """Answer ``GET /reports/...`` requests with a ``{"status", "body"}`` mapping."""

    def handle_request(self, method, path, params=None):
        """Entry point: dispatch one request."""
        params = params or {}
        try:
            if method == "GET" and path == "/reports/revenue":
                rows = service.revenue_report(params.get("unit", "month"), params.get("since"))
                return {"status": 200, "body": {"periods": serialize.revenue_rows(rows)}}
            if method == "GET" and path == "/reports/seasonality":
                rows = service.seasonality_report(params.get("part", "month"), params.get("since"))
                return {"status": 200, "body": {"parts": serialize.part_rows(rows)}}
            if method == "GET" and path == "/reports/customers":
                rows = service.top_customers_report(params.get("limit", "5"))
                return {"status": 200, "body": {"customers": serialize.customer_rows(rows)}}
        except ReportError as error:
            return {"status": error.status, "body": {"error": str(error)}}
        except sqlite3.Error:
            return {"status": 500, "body": {"error": "report failed"}}
        return {"status": 404, "body": {"error": "not found"}}


def create_app():
    """Build the reporting application."""
    return App()

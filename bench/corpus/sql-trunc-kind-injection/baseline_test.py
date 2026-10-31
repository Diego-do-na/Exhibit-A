"""Baseline for the report case: report behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after a fix: the three reports keep returning the same figures for
ordinary parameters.
"""

from salesreport import create_app


def get(path, **params):
    return create_app().handle_request("GET", path, params)


def test_revenue_per_month_counts_only_paid_orders():
    response = get("/reports/revenue", unit="month")
    assert response["status"] == 200
    assert response["body"]["periods"] == [
        {"period": "2023-11-01", "orders": 2, "revenue_cents": 21400},
        {"period": "2023-12-01", "orders": 1, "revenue_cents": 4300},
        {"period": "2024-01-01", "orders": 2, "revenue_cents": 28500},
        {"period": "2024-02-01", "orders": 3, "revenue_cents": 30800},
        {"period": "2024-03-01", "orders": 2, "revenue_cents": 20000},
    ]


def test_revenue_per_year_from_a_start_date():
    response = get("/reports/revenue", unit="year", since="2024-01-01")
    assert response["body"]["periods"] == [{"period": "2024-01-01", "orders": 7, "revenue_cents": 79300}]


def test_a_malformed_date_is_refused():
    assert get("/reports/revenue", unit="month", since="last week")["status"] == 400


def test_orders_per_month_of_the_year():
    response = get("/reports/seasonality", part="month")
    assert response["body"]["parts"] == [
        {"part": 1, "orders": 2},
        {"part": 2, "orders": 3},
        {"part": 3, "orders": 2},
        {"part": 11, "orders": 2},
        {"part": 12, "orders": 1},
    ]


def test_orders_per_year():
    response = get("/reports/seasonality", part="year")
    assert response["body"]["parts"] == [{"part": 2023, "orders": 3}, {"part": 2024, "orders": 7}]


def test_top_customers_by_paid_revenue():
    response = get("/reports/customers", limit="2")
    assert response["body"]["customers"] == [
        {"customer": "umbrella", "revenue_cents": 39900},
        {"customer": "globex", "revenue_cents": 26500},
    ]


def test_a_limit_that_is_not_a_number_is_refused():
    assert get("/reports/customers", limit="many")["status"] == 400


def test_unknown_routes_are_404():
    assert get("/reports/nothing")["status"] == 404

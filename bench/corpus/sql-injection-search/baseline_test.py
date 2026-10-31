"""Baseline for the search case: catalog behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after the fix: a real fix keeps searching, filtering
and sorting working while stopping request values from changing the
statement.
"""

from app import create_app


def names(response):
    return [item["name"] for item in response["body"]["items"]]


def test_unfiltered_listing_is_ordered_by_id():
    response = create_app().handle_request("GET", "/products")
    assert response["status"] == 200
    assert [item["id"] for item in response["body"]["items"]] == [1, 2, 3, 4, 5, 6, 7, 8]


def test_term_matches_part_of_a_name():
    response = create_app().handle_request("GET", "/products", {"q": "saw"})
    assert names(response) == ["hand saw"]


def test_categories_filter_with_a_list():
    response = create_app().handle_request("GET", "/products", {"category": ["tools", "garden"]})
    assert sorted(names(response)) == ["claw hammer", "garden hose", "hand saw", "plant pot", "screwdriver set"]


def test_sort_by_price_descending_with_a_limit():
    response = create_app().handle_request("GET", "/products", {"sort": "price_cents", "order": "desc", "limit": "2"})
    assert names(response) == ["chef knife", "cast iron pan"]


def test_single_product_and_missing_product():
    app = create_app()
    assert app.handle_request("GET", "/products/3")["body"]["product"]["name"] == "cast iron pan"
    assert app.handle_request("GET", "/products/99")["status"] == 404


def test_categories_and_unknown_routes():
    app = create_app()
    assert app.handle_request("GET", "/categories")["body"]["categories"] == ["garden", "kitchen", "tools"]
    assert app.handle_request("GET", "/nothing")["status"] == 404
    assert app.handle_request("POST", "/products")["status"] == 405

"""Baseline for the catalog expansion case: ordinary expressions keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps answering counts while running them in
linear time.
"""

from app import create_app


def test_plain_expression_returns_its_length():
    assert create_app().handle_request("123") == {"total": 3}


def test_short_expression_is_answered():
    assert create_app().handle_request("b2") == {"total": 2}


def test_count_shape_is_stable():
    first = create_app().handle_request("c3")
    second = create_app().handle_request("d4")
    assert (first, second) == ({"total": 2}, {"total": 2})

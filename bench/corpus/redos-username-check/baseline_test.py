"""Baseline for the directory search case: ordinary lookups keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps answering lookups while running them in
linear time.
"""

from app import create_app


def test_plain_lookup_misses():
    assert create_app().handle_request("123") == {"match": False}


def test_lookup_answers_quickly_for_ordinary_input():
    assert create_app().handle_request("b2") == {"match": False}


def test_lookup_shape_is_stable():
    first = create_app().handle_request("c3")
    second = create_app().handle_request("d4")
    assert first == second == {"match": False}

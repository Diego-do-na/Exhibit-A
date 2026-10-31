"""Baseline for the login case: account behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after the fix: a real fix keeps ordinary logins and
lookups working while stopping request values from changing the statement.
"""

from app import create_app


def test_valid_login_returns_the_account():
    response = create_app().handle_request("POST", "/login", {"username": "alice", "password": "alice-pass-1"})
    assert response["status"] == 200
    assert response["body"]["user"] == {"id": 1, "username": "alice", "role": "admin"}


def test_wrong_password_is_refused():
    response = create_app().handle_request("POST", "/login", {"username": "alice", "password": "nope"})
    assert response["status"] == 401


def test_unknown_user_is_refused():
    response = create_app().handle_request("POST", "/login", {"username": "mallory", "password": "x"})
    assert response["status"] == 401


def test_user_lookup_by_id():
    response = create_app().handle_request("GET", "/users/2")
    assert response["status"] == 200
    assert response["body"]["user"]["username"] == "bob"


def test_unknown_id_and_unknown_route_are_not_found():
    app = create_app()
    assert app.handle_request("GET", "/users/99")["status"] == 404
    assert app.handle_request("GET", "/nothing")["status"] == 404

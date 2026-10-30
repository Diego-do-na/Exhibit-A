"""Baseline for the demo app: behaviour that must keep working on every branch.

It deliberately has no path-escape test. The proof loop writes its own exploit test, and a
baseline that already failed on the vulnerable branch would abort the run before any proof.
"""

from pamphlets import create_app


def _shelf(tmp_path):
    shelf = tmp_path / "shelf"
    shelf.mkdir()
    (shelf / "welcome.txt").write_text("hello reader", encoding="utf-8")
    (shelf / "rules.txt").write_text("be kind", encoding="utf-8")
    return create_app(str(shelf))


def test_serves_a_pamphlet(tmp_path):
    response = _shelf(tmp_path).handle_request("GET", "/pamphlet", {"name": "welcome.txt"})
    assert (response.status, response.body) == (200, "hello reader")


def test_missing_pamphlet_is_not_found(tmp_path):
    response = _shelf(tmp_path).handle_request("GET", "/pamphlet", {"name": "nope.txt"})
    assert response.status == 404


def test_index_lists_names_sorted(tmp_path):
    response = _shelf(tmp_path).handle_request("GET", "/index")
    assert response.body.split("\n") == ["rules.txt", "welcome.txt"]


def test_only_get_is_allowed(tmp_path):
    assert _shelf(tmp_path).handle_request("POST", "/index").status == 405


def test_unknown_path_is_not_found(tmp_path):
    assert _shelf(tmp_path).handle_request("GET", "/other").status == 404

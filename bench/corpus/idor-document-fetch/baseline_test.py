"""Baseline for the library document case: ordinary reads keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps owners reading their own documents while
refusing everyone else.
"""

from app import create_app


def test_owner_reads_their_own_document():
    response = create_app().handle_request("viewer.ann", "samples/welcome")
    assert response["status"] == 200
    assert "Welcome" in response["body"]["document"]


def test_a_missing_document_is_an_error():
    try:
        create_app().handle_request("viewer.ann", "no-such-document")
    except KeyError:
        return
    raise AssertionError("a missing document should be an error")


def test_trailing_slash_reads_the_same_document():
    first = create_app().handle_request("viewer.ann", "samples/welcome")
    second = create_app().handle_request("viewer.ann", "samples/welcome/")
    assert first["body"]["document"] == second["body"]["document"]

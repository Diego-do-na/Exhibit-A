"""Baseline for the job-intake case: behaviour kept on every tree."""

from app import create_app

JOB = "name: sort\nlimit: 10\n"


def test_loads_a_plain_job(tmp_path):
    app = create_app(str(tmp_path))
    job = app.handle_request("POST", JOB)
    assert job["name"] == "sort"
    assert job["limit"] == 10


def test_loads_a_nested_job(tmp_path):
    app = create_app(str(tmp_path))
    job = app.handle_request("POST", "task:\n  name: pack\n")
    assert job["task"]["name"] == "pack"


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", JOB) == "method not allowed"

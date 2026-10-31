"""Baseline for the deserialization case: intake behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after the fix: a real fix keeps ordinary JSON
intakes decoding while no longer unpickling request bytes.
"""

import json

import pytest

from app import create_app


def _post(blob):
    return create_app("base").handle_request("POST", blob)


def test_decodes_a_json_intake(tmp_path):
    blob = json.dumps({"items": ["a", "b"]}).encode("utf-8")
    assert _post(blob) == {"items": ["a", "b"]}


def test_non_post_requests_are_rejected():
    assert create_app("base").handle_request("GET", b"{}") == "method not allowed"


def test_an_undecodable_blob_is_rejected():
    with pytest.raises(Exception):
        _post(b"\xff-not-a-job")

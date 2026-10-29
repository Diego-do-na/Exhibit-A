"""Synthetic app for the advisory reachability tests (never executed)."""

from fictional_webkit.static import serve_file


def download(name):
    return serve_file(name)

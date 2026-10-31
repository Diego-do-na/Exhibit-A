"""Export formats."""

import html

from ..errors import BadRequest

FORMATS = ("txt", "html", "bundle")


def check_format(name):
    """The format name, or a 400 for an unknown one."""
    if name not in FORMATS:
        raise BadRequest(f"unknown export format: {name}")
    return name


def render_txt(document):
    """A document as plain text."""
    lines = [document.title, "=" * len(document.title), "", document.body]
    if document.tags:
        lines += ["", "Tags: " + ", ".join(document.tags)]
    return "\n".join(lines) + "\n"


def render_html(document):
    """A document as a small standalone HTML page."""
    body = html.escape(document.body).replace("\n", "<br>")
    tags = "".join(f"<li>{html.escape(tag)}</li>" for tag in document.tags)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(document.title)}</title></head><body>"
        f"<h1>{html.escape(document.title)}</h1><p>{body}</p>"
        f"<ul>{tags}</ul></body></html>\n"
    )


def extension(name):
    """The file ending used for an export of ``name``."""
    return {"txt": ".txt", "html": ".html", "bundle": ".bundle"}[check_format(name)]

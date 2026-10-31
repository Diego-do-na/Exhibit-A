"""Turning one document into export bytes."""

from .formats import check_format, render_html, render_txt


def render(document, name):
    """The bytes of ``document`` rendered as ``name`` (``bundle`` excluded)."""
    check_format(name)
    if name == "txt":
        return render_txt(document).encode("utf-8")
    if name == "html":
        return render_html(document).encode("utf-8")
    raise ValueError("bundle exports are assembled by the bundle writer")


def describe(document, name):
    """A short mapping describing what rendering ``document`` as ``name`` yields."""
    payload = render(document, name) if name != "bundle" else b""
    return {"format": check_format(name), "bytes": len(payload),
            "title": document.title}

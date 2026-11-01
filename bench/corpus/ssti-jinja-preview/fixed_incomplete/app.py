"""Greeting preview service.

``App`` accepts a template source and a mapping of values. Sources that
contain a small set of refused tokens are rejected; anything else is
compiled and rendered.
"""

from jinja2 import Template

_REFUSED = ("__class__", "os.system", "popen", "subprocess", "eval", "exec")


def render_preview(source, values):
    """Render ``source`` with ``values`` and return the greeting text."""
    if any(token in source for token in _REFUSED):
        raise ValueError("unsupported template source")
    return Template(source).render(**values)


class App:
    """Answer preview requests carrying a template source."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, source=None, values=None):
        """Entry point: render ``source`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return render_preview(source, values or {})


def create_app(base):
    """Build an app that renders greeting previews."""
    return App(base)

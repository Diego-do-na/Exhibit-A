"""Greeting preview service.

``App`` accepts a template source and a mapping of values, compiles the
source in a sandboxed environment, and returns the rendered greeting.
"""

from jinja2.sandbox import SandboxedEnvironment


def render_preview(source, values):
    """Render ``source`` with ``values`` and return the greeting text."""
    return SandboxedEnvironment().from_string(source).render(**values)


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

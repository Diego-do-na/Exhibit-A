"""Order notification service.

``App`` answers notification requests carrying a subject line and order
values, renders the subject as a template and returns the message.
"""

from jinja2 import Environment


def render_subject(subject, values):
    """Render ``subject`` as a template with ``values``."""
    return Environment().from_string("Order update: " + subject).render(**values)


class App:
    """Answer notification requests carrying a subject line."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, subject=None, values=None):
        """Entry point: render ``subject`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return render_subject(subject, values or {})


def create_app(base):
    """Build an order notification service."""
    return App(base)

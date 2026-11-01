"""Job intake service for the background worker queue.

``App`` accepts intake requests carrying a job description as YAML. A
request is handled by loading the attached document into a job object.
"""

import yaml


def load_job(document):
    """Load a job description from a YAML document."""
    return yaml.unsafe_load(document)


class App:
    """Accept intake requests carrying a job document."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, document=None):
        """Entry point: load the attached ``document`` on POST."""
        if method != "POST":
            return "method not allowed"
        return load_job(document)


def create_app(base):
    """Build an app that loads job documents."""
    return App(base)

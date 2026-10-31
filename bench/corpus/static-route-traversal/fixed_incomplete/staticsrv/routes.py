"""Static routes: a URL prefix served from a directory."""

import os
from urllib.parse import unquote

from .content import content_type
from .files import describe, read_body
from .response import Response, not_found


def inside(path, directory):
    """Whether ``path`` is ``directory`` or lies below it."""
    return path == directory or path.startswith(directory + os.sep)


class StaticRoute:
    """Serve the files below ``directory`` under the URL ``prefix``.

    With ``follow_symlinks`` a link inside the directory may point anywhere. Directory
    requests are answered with the ``index`` file when there is one.
    """

    def __init__(self, prefix, directory, follow_symlinks=False, index="index.html"):
        self.prefix = "/" + prefix.strip("/")
        self.directory = os.path.realpath(directory)
        self.follow_symlinks = follow_symlinks
        self.index = index

    def matches(self, path):
        """Whether a request path belongs to this route."""
        return path == self.prefix or path.startswith(self.prefix + "/")

    def relative_name(self, path):
        """The file name a request path asks for, relative to the route's directory."""
        return unquote(path[len(self.prefix) + 1:])

    def resolve(self, name):
        """The real path of the file ``name`` stands for, or None when it may not be served."""
        real = os.path.realpath(os.path.join(self.directory, name))
        if not self.follow_symlinks and not inside(real, self.directory):
            return None
        if os.path.isdir(real):
            real = os.path.join(real, self.index)
        return real if os.path.isfile(real) else None

    def serve(self, method, path, headers):
        """Answer one request for a path of this route."""
        if ".." in path.split("/"):
            return not_found()
        target = self.resolve(self.relative_name(path))
        if target is None:
            return not_found()
        validator = describe(target)
        reply_headers = {"content-type": content_type(target), "etag": '"' + validator + '"'}
        if headers.get("if-none-match") == reply_headers["etag"]:
            return Response(304, b"", reply_headers)
        body = read_body(target)
        reply_headers["content-length"] = str(len(body))
        return Response(200, b"" if method == "HEAD" else body, reply_headers)

import os

from . import workers


class StaticFiles:
    """Serves files below one directory (fixture: the shape of a static-file ASGI app)."""

    def __init__(self, directory):
        self.directory = directory

    async def __call__(self, scope, receive, send):
        path = self.get_path(scope)
        body = await self.get_response(path)
        await send({"type": "http.response.body", "body": body})

    def get_path(self, scope):
        return os.path.normpath(scope["path"].lstrip("/"))

    async def get_response(self, path):
        full_path, size = await workers.in_thread(self.lookup_path, path)
        if size is None:
            return b"not found"
        return b"found"

    def lookup_path(self, path):
        full_path = os.path.realpath(os.path.join(self.directory, path))
        if not full_path.startswith(self.directory):
            return full_path, None
        return full_path, os.stat(full_path).st_size

import os

from helpers import format_name, orphan


class Files:
    def __init__(self, root):
        self.root = root

    async def __call__(self, scope, receive, send):
        name = format_name(scope["path"])
        with open(os.path.join(self.root, name), encoding="utf-8") as handle:
            await send({"type": "http.response.body", "body": handle.read().encode()})


def unused():
    return orphan("x")

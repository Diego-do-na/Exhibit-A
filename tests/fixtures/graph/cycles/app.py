import os


class App:
    def __init__(self, root):
        self.root = root

    def handle_request(self, method, path):
        return self.visit(path, 3)

    def visit(self, path, depth):
        if depth <= 0:
            return self.serve(path)
        return self.walk(path, depth)

    def walk(self, path, depth):
        return self.visit(path, depth - 1)

    def serve(self, path):
        return countdown(len(path)) or read(os.path.join(self.root, path))


def countdown(n):
    return n if n <= 0 else countdown(n - 1)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()

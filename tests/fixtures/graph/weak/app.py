import os


class Reader:
    def fetch_document(self, name):
        return open(os.path.join("/srv", name)).read()


class App:
    def __init__(self, backend):
        self.backend = backend

    def handle_request(self, method, name):
        return self.backend.fetch_document(name)

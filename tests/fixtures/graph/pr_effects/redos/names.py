import re

PATTERN = re.compile(r"^([a-zA-Z0-9_]+)+$")


def is_username(name):
    return bool(PATTERN.match(name))


class App:
    def handle_request(self, method, path, query):
        return is_username(query.get("name", ""))

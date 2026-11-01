import re


class App:
    def handle_request(self, data):
        if len(data) > 32:
            raise ValueError("too long")
        return bool(re.search(r"a+$", data))

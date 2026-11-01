import re


class App:
    def handle_request(self, data):
        return bool(re.search(r"(a+)+$", data))

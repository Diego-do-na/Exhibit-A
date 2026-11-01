import urllib.parse

ALLOWED = {"shop.example.com"}


class App:
    def handle_request(self, target):
        host = urllib.parse.urlsplit(target).hostname or ""
        if host not in ALLOWED:
            raise ValueError("refusing an off-site redirect")
        return (302, {"Location": target}, "Found")

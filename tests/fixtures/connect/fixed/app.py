import urllib.parse
import urllib.request

ALLOWED = {"api.example.com"}


class App:
    def handle_request(self, url):
        host = urllib.parse.urlsplit(url).hostname or ""
        if host not in ALLOWED:
            raise ValueError("host not allowed: " + host)
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()

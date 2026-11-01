import urllib.request


class App:
    def handle_request(self, url):
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()

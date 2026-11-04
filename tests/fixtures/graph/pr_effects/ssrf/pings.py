import urllib.request


class App:
    def handle_request(self, method, path, query):
        url = query.get("url", "")
        return urllib.request.urlopen(url).read()

FOLDERS = {
    "1": {"owner": "alice", "body": "secret"},
    "2": {"owner": "bob", "body": "other"},
}


class App:
    def handle_request(self, method, path, query):
        folder = FOLDERS.get(query.get("id", ""))
        if folder is None:
            return None
        return folder["body"]

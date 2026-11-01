import json
import os

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")


class App:
    def handle_request(self, auth, resource):
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        entry = store[resource]
        if entry["owner"] != auth:
            raise PermissionError("not the owner of this resource")
        return entry["content"]

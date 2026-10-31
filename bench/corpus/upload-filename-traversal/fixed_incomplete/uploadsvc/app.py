"""The application: routes requests to the upload use cases."""

from .errors import UploadError
from .service import list_files, store_upload
from .storage import FileStorage


class App:
    """Answer ``POST /upload`` and ``GET /files``."""

    def __init__(self, storage):
        self.storage = storage

    def handle_request(self, method, path, headers=None, body=b""):
        """Entry point: answer one request with a ``(status, payload)`` pair."""
        headers = {key.lower(): value for key, value in (headers or {}).items()}
        try:
            if method == "POST" and path == "/upload":
                names = store_upload(self.storage, headers.get("content-type", ""), body)
                return 201, {"stored": names}
            if method == "GET" and path == "/files":
                return 200, {"files": list_files(self.storage)}
        except UploadError as error:
            return error.status, {"error": str(error)}
        return 404, {"error": "not found"}


def create_app(directory):
    """Build the service storing uploads below ``directory``."""
    return App(FileStorage(directory))

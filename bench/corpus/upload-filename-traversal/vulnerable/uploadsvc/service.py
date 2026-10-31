"""Use cases of the upload service."""

from .config import MAX_BODY_BYTES, MAX_FILES_PER_REQUEST
from .errors import MalformedBody, TooLarge
from .multipart import boundary_of, parse
from .uploaded import UploadedFile


def store_upload(storage, content_type, body):
    """Store every file of a multipart request and return the stored names."""
    if len(body) > MAX_BODY_BYTES:
        raise TooLarge("request body is over the limit")
    files = [part for part in parse(body, boundary_of(content_type)) if part.filename is not None]
    if not files:
        raise MalformedBody("no file in the request")
    if len(files) > MAX_FILES_PER_REQUEST:
        raise TooLarge("too many files")
    stored = []
    for part in files:
        uploaded = UploadedFile(part.filename, part.data)
        stored.append(storage.save(uploaded.name, uploaded.data))
    return stored


def list_files(storage):
    """The names of the stored files."""
    return storage.names()

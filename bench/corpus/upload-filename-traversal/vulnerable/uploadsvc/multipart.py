"""Reading and writing multipart/form-data bodies."""

from .errors import MalformedBody


class Part:
    """One form field: its name, the file name it carries (or None) and its bytes."""

    def __init__(self, field, filename, data):
        self.field = field
        self.filename = filename
        self.data = data


def boundary_of(content_type):
    """The boundary token of a multipart Content-Type header value."""
    if not content_type or not content_type.lower().startswith("multipart/form-data"):
        raise MalformedBody("not a multipart/form-data request")
    for item in content_type.split(";")[1:]:
        key, _, value = item.strip().partition("=")
        if key.lower() == "boundary" and value:
            return value.strip('"')
    raise MalformedBody("no boundary")


def _disposition(header_block):
    """The ``name`` and ``filename`` parameters of a part's Content-Disposition header."""
    params = {}
    for line in header_block.split("\r\n"):
        key, _, value = line.partition(":")
        if key.strip().lower() != "content-disposition":
            continue
        for item in value.split(";")[1:]:
            name, _, raw = item.strip().partition("=")
            params[name.lower()] = raw.strip('"')
    if "name" not in params:
        raise MalformedBody("part without a field name")
    return params


def parse(body, boundary):
    """Split a multipart body into its parts."""
    delimiter = b"--" + boundary.encode("ascii", "replace")
    chunks = body.split(delimiter)
    if len(chunks) < 3 or not chunks[-1].startswith(b"--"):
        raise MalformedBody("body does not end with the closing boundary")
    parts = []
    for chunk in chunks[1:-1]:
        chunk = chunk.removeprefix(b"\r\n")
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            raise MalformedBody("part without a header block")
        params = _disposition(head.decode("utf-8", "replace"))
        parts.append(Part(params["name"], params.get("filename"), data.removesuffix(b"\r\n")))
    return parts


def encode(boundary, parts):
    """Build a multipart body from ``(field, filename, data)`` triples."""
    out = b""
    for field, filename, data in parts:
        disposition = f'form-data; name="{field}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        out += f"--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n".encode("utf-8") + data + b"\r\n"
    return out + f"--{boundary}--\r\n".encode("ascii")

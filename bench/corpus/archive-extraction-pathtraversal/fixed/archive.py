"""Tiny archive extractor that confines every member to the destination (case fixture, fixed).

This is the fixed variant of the vulnerable extractor. The one real change is in ``_target``:
the resolved target must lie inside the destination directory, which rejects both ``..``
traversal and absolute member paths. The real-world fix for the analogous CVE-2007-4559 is
``tarfile``'s ``filter="data"`` option (PEP 706); this case uses an original, equivalent
containment check. No third-party code is used.

The engine runs this inside an isolated and resource-limited sandbox; it is never "100% safe".
"""

import os

# Container format (bytes): for each member, an ASCII header line "<name_len> <data_len>\n"
# followed by the UTF-8 name bytes and then the UTF-8 data bytes. Members are concatenated.


class Member:
    """One file in an archive: the path recorded in the archive and its content."""

    def __init__(self, name, data):
        self.name = name
        self.data = data


def pack(members):
    """Serialise ``(name, data)`` pairs into the archive byte format."""
    chunks = []
    for name, data in members:
        name_bytes = name.encode("utf-8")
        data_bytes = data.encode("utf-8")
        header = f"{len(name_bytes)} {len(data_bytes)}\n".encode("ascii")
        chunks.append(header + name_bytes + data_bytes)
    return b"".join(chunks)


def unpack(blob):
    """Parse the archive byte format back into a list of ``Member`` objects."""
    members = []
    index = 0
    length = len(blob)
    while index < length:
        newline = blob.index(b"\n", index)
        name_len, data_len = (int(part) for part in blob[index:newline].split())
        index = newline + 1
        name = blob[index:index + name_len].decode("utf-8")
        index += name_len
        data = blob[index:index + data_len].decode("utf-8")
        index += data_len
        members.append(Member(name, data))
    return members


class Extractor:
    """Writes each archive member to disk under a destination directory."""

    def __init__(self, dest_dir):
        self.dest_dir = dest_dir

    def _target(self, name):
        # Fix: confine the resolved target to the destination directory. os.path.realpath
        # collapses ".." and resolves an absolute name to itself, so anything that does not
        # stay under dest_dir is rejected before a single byte is written.
        dest = os.path.realpath(self.dest_dir)
        target = os.path.realpath(os.path.join(dest, name))
        if target != dest and not target.startswith(dest + os.sep):
            raise ValueError(f"archive member escapes destination: {name!r}")
        return target

    def extract_member(self, member):
        """Sink: write one member to the path derived from its name."""
        target = self._target(member.name)
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(member.data)
        return target

    def extract_all(self, members):
        """Extract every member; members a safer policy rejects are skipped."""
        written = []
        for member in members:
            try:
                written.append(self.extract_member(member))
            except ValueError:
                continue
        return written


class App:
    """Small app that extracts an uploaded archive into its upload directory."""

    def __init__(self, dest_dir):
        self.extractor = Extractor(dest_dir)

    def handle_request(self, method, blob=None):
        """Entry point: handle an upload request carrying an archive ``blob``."""
        if method != "POST":
            return "method not allowed"
        return self.extractor.extract_all(unpack(blob))


def create_app(dest_dir):
    """Build an app that extracts archives into ``dest_dir`` without confining member paths."""
    return App(dest_dir)

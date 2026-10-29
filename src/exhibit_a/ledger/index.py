"""runs.jsonl: append-only run index, one JSON line per run.

Each record is written with a single os.write on an O_APPEND descriptor, so concurrent
writers (threads or processes) cannot interleave inside a line. Reading never raises on
bad content: corrupt, invalid or oversized lines are reported in `problems`.
"""

import json
import os
from pathlib import Path

from pydantic import ValidationError

from exhibit_a.schemas.run_index import RunRecord

MAX_LINE_BYTES = 64 * 1024


def append_run(index_path: str | os.PathLike, record: RunRecord | dict) -> None:
    """Validate `record` and append it as one line; raises ValueError if invalid or too big."""
    if not isinstance(record, RunRecord):
        record = RunRecord.model_validate(record)
    line = record.model_dump_json() + "\n"
    data = line.encode("utf-8")
    if len(data) > MAX_LINE_BYTES:
        raise ValueError(f"run record exceeds {MAX_LINE_BYTES} bytes")
    fd = os.open(index_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("short write to run index")
    finally:
        os.close(fd)


def read_runs(index_path: str | os.PathLike) -> tuple[list[RunRecord], list[str]]:
    """Return (valid records, problems). A missing file is an empty index."""
    records: list[RunRecord] = []
    problems: list[str] = []
    path = Path(index_path)
    if not path.exists():
        return records, problems
    with path.open("rb") as handle:
        lineno = 0
        while True:
            raw = handle.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            lineno += 1
            if len(raw) > MAX_LINE_BYTES and not raw.endswith(b"\n"):
                while raw and not raw.endswith(b"\n"):  # drain the rest of the oversized line
                    raw = handle.readline(MAX_LINE_BYTES)
                problems.append(f"line {lineno}: oversized (> {MAX_LINE_BYTES} bytes)")
                continue
            if not raw.endswith(b"\n"):
                problems.append(f"line {lineno}: truncated (no trailing newline)")
                continue
            if not raw.strip():
                continue
            try:
                records.append(RunRecord.model_validate(json.loads(raw)))
            except (ValueError, ValidationError, RecursionError) as exc:
                problems.append(f"line {lineno}: {type(exc).__name__}: {str(exc).splitlines()[0]}")
    return records, problems

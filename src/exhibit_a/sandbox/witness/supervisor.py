"""In-container OS witness. Stdlib only; mounted as a single file next to the plugin.

Started by the sandbox runner before pytest, as a sibling of the test (not in its process
tree). Reads a per-run config (including the HMAC key), unlinks that file, watches the
canary at the OS level, and appends signed observations to the witness log. The test
process never receives the key. Isolated and resource-limited, not "100% safe".
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import select
import signal
import struct
import sys
import threading
import time

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_OPEN = 0x00000020
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_Q_OVERFLOW = 0x00004000
IN_CLOEXEC = 0x00080000
IN_NONBLOCK = 0x00000800
IN_DONT_FOLLOW = 0x02000000

FILE_MASK = IN_ACCESS | IN_MODIFY | IN_CLOSE_WRITE | IN_OPEN | IN_ATTRIB
DIR_MASK = FILE_MASK | IN_CREATE | IN_MOVED_TO | IN_DELETE
EVENT_HDR = ctypes.sizeof(ctypes.c_int) + 12  # wd + mask + cookie + len


def _canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _signed_line(key: bytes, seq: int, body: dict) -> str:
    payload = f"{seq}\n{_canonical(body)}".encode("ascii")
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return json.dumps({"body": body, "seq": seq, "sig": sig}, ensure_ascii=True) + "\n"


class _Log:
    def __init__(self, path: str, key: bytes) -> None:
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
        self._key = key
        self._seq = 0
        self._lock = threading.Lock()

    def emit(self, body: dict) -> None:
        with self._lock:
            line = _signed_line(self._key, self._seq, body)
            self._seq += 1
            os.write(self._fd, line.encode("ascii"))

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


def _libc():
    lib = ctypes.CDLL("libc.so.6", use_errno=True)
    lib.inotify_init1.argtypes = [ctypes.c_int]
    lib.inotify_init1.restype = ctypes.c_int
    lib.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    lib.inotify_add_watch.restype = ctypes.c_int
    return lib


def _add_watch(lib, fd: int, path: str, mask: int) -> int:
    wd = lib.inotify_add_watch(fd, path.encode("utf-8"), mask)
    if wd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), path)
    return wd


def _existing_ancestor(path: str) -> str:
    here = path
    while here not in ("/", "") and not os.path.isdir(here) and not os.path.lexists(here):
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    if os.path.isdir(here):
        return here
    parent = os.path.dirname(here)
    return parent if parent else here


class _Watcher:
    """inotify watches on canary paths; directory watches follow newly created children."""

    def __init__(self, lib, log: _Log, effect: str, targets: list[str]) -> None:
        self.lib = lib
        self.log = log
        self.effect = effect
        self.targets = [os.path.abspath(t) for t in targets]
        self.basenames = {os.path.basename(t) for t in self.targets if os.path.basename(t)}
        self.wd_to_dir: dict[int, str] = {}
        self.wd_to_path: dict[int, str] = {}
        self.fd = lib.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if self.fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno), "inotify_init1")
        roots = []
        for target in self.targets:
            if os.path.isdir(target):
                roots.append(target)
            elif os.path.lexists(target):
                self._watch_file(target)
                roots.append(os.path.dirname(target) or "/")
            else:
                roots.append(_existing_ancestor(target))
        for root in dict.fromkeys(roots):
            if os.path.isdir(root):
                self._watch_tree(root)

    def _watch_file(self, path: str) -> None:
        try:
            wd = _add_watch(self.lib, self.fd, path, FILE_MASK)
        except OSError:
            return
        self.wd_to_path[wd] = path

    def _watch_dir(self, path: str) -> None:
        try:
            wd = _add_watch(self.lib, self.fd, path, DIR_MASK)
        except OSError:
            return
        self.wd_to_dir[wd] = path
        self.wd_to_path[wd] = path

    def _watch_tree(self, root: str) -> None:
        self._watch_dir(root)
        try:
            entries = list(os.scandir(root))
        except OSError:
            return
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    self._watch_tree(entry.path)
                elif entry.is_file(follow_symlinks=False) and self._is_target(entry.path):
                    self._watch_file(entry.path)
            except OSError:
                continue

    def _event_path(self, wd: int, name: str) -> str | None:
        base = self.wd_to_dir.get(wd)
        if base is not None:
            return os.path.join(base, name) if name else base
        return self.wd_to_path.get(wd)

    def _is_target(self, path: str) -> bool:
        abspath = os.path.abspath(path)
        if abspath in self.targets:
            return True
        try:
            real = os.path.realpath(abspath)
        except OSError:
            real = abspath
        for target in self.targets:
            try:
                if real == os.path.realpath(target):
                    return True
            except OSError:
                if real == os.path.abspath(target):
                    return True
        return os.path.basename(abspath) in self.basenames

    def drain(self) -> None:
        while True:
            try:
                raw = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            except OSError:
                return
            if not raw:
                return
            offset = 0
            while offset + EVENT_HDR <= len(raw):
                wd, mask, _cookie, length = _unpack_event(raw, offset)
                offset += EVENT_HDR
                name = ""
                if length:
                    end = offset + length
                    if end > len(raw):
                        return
                    name = raw[offset:end].split(b"\0", 1)[0].decode("utf-8", "replace")
                    offset = end
                if mask & IN_Q_OVERFLOW:
                    self.log.emit({"kind": "overflow", "effect": self.effect, "path": "", "mask": int(mask)})
                    continue
                path = self._event_path(wd, name)
                if path is None:
                    continue
                if mask & IN_CREATE:
                    try:
                        if os.path.isdir(path) and not os.path.islink(path):
                            self._watch_tree(path)
                    except OSError:
                        pass
                if self._is_target(path) and mask & (FILE_MASK | IN_CREATE | IN_MOVED_TO):
                    self.log.emit({
                        "kind": "access",
                        "effect": self.effect,
                        "path": path[:4096],
                        "mask": int(mask),
                    })

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


def _unpack_event(raw: bytes, offset: int) -> tuple[int, int, int, int]:
    return struct.unpack_from("iIII", raw, offset)


def _read_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not isinstance(cfg, dict):
        raise ValueError("witness config must be an object")
    try:
        os.unlink(path)
    except OSError:
        pass
    return cfg


def _start_listener(cfg: dict, log: _Log, effect: str) -> object:
    """Run the loopback canary listener inside this process so accept() is the OS fact."""
    connect = cfg.get("connect")
    if not isinstance(connect, dict):
        return None
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    if plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)
    import canary_server  # mounted read-only beside this file

    port = int(connect["port"])
    secret = str(connect["secret"])
    token = str(connect["token"])
    connect_log = str(connect["connect_log"])
    url = str(connect.get("url") or "")

    class WitnessServer(canary_server._Server):
        def process_request(self, request, client_address):  # noqa: ANN001
            peer = ""
            try:
                peer = client_address[0] if client_address else ""
            except (IndexError, TypeError):
                peer = ""
            log.emit({
                "kind": "accept",
                "effect": effect,
                "path": url[:4096],
                "peer": str(peer)[:64],
            })
            super().process_request(request, client_address)

    server = WitnessServer(("127.0.0.1", port), secret, token, connect_log)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _ready(path: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    os.write(fd, b"ok\n")
    os.close(fd)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: witness.py CONFIG", file=sys.stderr)
        return 2
    try:
        cfg = _read_config(argv[1])
        key = bytes.fromhex(str(cfg["key"]))
        effect = str(cfg["effect"])
        log_path = str(cfg["log"])
        ready_path = str(cfg["ready"])
        paths = [str(p) for p in cfg.get("paths") or [] if str(p)]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"witness config: {exc}", file=sys.stderr)
        return 1
    if len(key) != 32 or not effect or not log_path or not ready_path:
        print("witness config is incomplete", file=sys.stderr)
        return 1

    log = _Log(log_path, key)
    watcher = None
    server = None
    stopping = [False]

    def stop(signum, frame):  # noqa: ANN001, ARG001
        stopping[0] = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        log.emit({"kind": "start", "effect": effect, "path": "", "mask": 0})
        if paths:
            watcher = _Watcher(_libc(), log, effect, paths)
        if cfg.get("connect"):
            server = _start_listener(cfg, log, effect)
        _ready(ready_path)
        while not stopping[0]:
            if watcher is None:
                time.sleep(0.1)
                continue
            readable, _, _ = select.select([watcher.fd], [], [], 0.2)
            if readable:
                watcher.drain()
        if watcher is not None:
            watcher.drain()
        log.emit({"kind": "stop", "effect": effect, "path": "", "mask": 0})
        return 0
    except OSError as exc:
        try:
            log.emit({"kind": "overflow", "effect": effect, "path": str(exc)[:300], "mask": 0})
        except OSError:
            pass
        return 1
    finally:
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
        if watcher is not None:
            watcher.close()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

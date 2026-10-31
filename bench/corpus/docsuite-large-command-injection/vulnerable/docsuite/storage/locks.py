"""Cooperative in-process locks for one running service."""

import threading
from contextlib import contextmanager


class LockSet:
    """Named re-entrant locks, one per key."""

    def __init__(self):
        self._guard = threading.Lock()
        self._locks = {}

    def _lock_for(self, key):
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._locks[key] = lock
            return lock

    def acquire(self, key):
        """Take the lock for ``key``."""
        self._lock_for(key).acquire()

    def release(self, key):
        """Release the lock for ``key``."""
        self._lock_for(key).release()

    @contextmanager
    def hold(self, key):
        """Hold the lock for ``key`` for the body of the ``with`` block."""
        self.acquire(key)
        try:
            yield key
        finally:
            self.release(key)

    def locked_keys(self):
        """The keys that currently have a lock object."""
        with self._guard:
            return sorted(self._locks)

"""Pluggable key-value storage for short-lived federation/OIDC state (authorization codes,
PAR request URIs, cached entity statements).

`pop` exists as its own method, not as a convenience wrapper around `get` + `delete`,
because authorization codes and similar one-time values must be single-use: a caller
doing "get, check it, then delete" leaves a window where two concurrent requests can both
read the same code before either deletes it, and both succeed. `pop` closes that window by
making the read-and-delete a single atomic step.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable

__all__ = ["Store", "InMemoryStore"]


@runtime_checkable
class Store(Protocol):
    """The storage contract every backend (in-memory, database, Redis) implements.

    Values are always `bytes` -- callers own their own serialization (JSON, raw JWT
    text, etc.) so this protocol stays agnostic to what is actually being stored.
    """

    def get(self, key: str) -> bytes | None:
        """Return the value for `key`, or None if absent or expired."""
        ...

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        """Store `value` under `key`, to expire after `ttl_seconds`."""
        ...

    def pop(self, key: str) -> bytes | None:
        """Atomically read and remove `key`, returning its value or None. See module docstring."""
        ...

    def delete(self, key: str) -> None:
        """Remove `key` if present. A no-op if it is already absent or expired."""
        ...


class InMemoryStore:
    """A `Store` backed by a plain dict, guarded by a `threading.Lock`.

    For development and single-process deployments only: state lives in this process's
    memory, so it does not survive a restart and is not shared across workers. Database-
    and Redis-backed stores for multi-process/production use land in the Django package
    (see the project roadmap); this one exists so the core library and its tests have no
    dependency on either.

    TTL expiry is evaluated lazily, on read (`get`/`pop`) rather than by a background
    sweep -- there is no reaper thread, so an expired entry that is never read again just
    sits in the dict until the process exits. Fine for the short-lived values this store
    is meant for; not a concern worth solving without a real workload demanding it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[bytes, float]] = {}

    def get(self, key: str) -> bytes | None:
        with self._lock:
            return self._get_locked(key)

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        expires_at = time.monotonic() + ttl_seconds
        with self._lock:
            self._entries[key] = (value, expires_at)

    def pop(self, key: str) -> bytes | None:
        with self._lock:
            value = self._get_locked(key)
            self._entries.pop(key, None)
            return value

    def delete(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def _get_locked(self, key: str) -> bytes | None:
        """Look up `key` and evict it in place if its TTL has elapsed. Caller holds `_lock`."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() >= expires_at:
            del self._entries[key]
            return None
        return value

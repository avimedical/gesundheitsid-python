"""Three `gesundheitsid.storage.Store` implementations for Django, selected by
`GESUNDHEITSID["STORE_BACKEND"]`: `CacheStore`, `DatabaseStore`, and (re-exported)
`InMemoryStore`.

Authorization codes and PAR state are single-use by contract -- see `Store.pop`'s own
docstring. Each backend's `pop` is documented below with exactly what it guarantees and
why; do not upgrade any of that wording without re-verifying the guarantee still holds,
see `tests/django/test_stores.py`'s concurrency test.
"""

from __future__ import annotations

import datetime

from django.core.cache import caches
from django.db import transaction
from django.utils import timezone

from django_gesundheitsid.conf import StoreBackend, get_settings
from django_gesundheitsid.models import StoredEntry
from gesundheitsid.storage import InMemoryStore, Store

__all__ = ["CacheStore", "DatabaseStore", "InMemoryStore", "get_store"]

#: sentinel distinguishing "this cache has no GETDEL path" from a real `None` pop result.
_NOT_REDIS = object()


class CacheStore:
    """A `Store` backed by a Django cache alias -- `LocMemCache` in development/CI,
    `django_redis.cache.RedisCache` in production, and anything else Django's cache
    framework supports in between.

    TTL is delegated entirely to the cache backend's own expiry; this class never checks
    `expires_at` itself the way `DatabaseStore` has to.

    `pop`'s atomicity is backend-dependent -- there is no atomic get-and-delete in
    Django's cache API itself:

    * Against `django_redis.cache.RedisCache`, `pop` reaches through to the underlying
      `redis-py` client and issues a single `GETDEL` command (Redis >= 6.2). That is a
      genuine atomic read-and-remove at the server: two callers racing to pop the same
      key will never both receive a non-None value.
    * Against every other cache backend (`LocMemCache` included), `pop` falls back to
      `get()` immediately followed by `delete()` -- **not atomic**. Two callers racing
      inside that window can both observe the value before either deletes it, and both
      "win". `LocMemCache` is fine for single-process development/CI since Python's GIL
      serializes the two calls against its internal lock enough that a genuine concurrent
      *request* handler race is the only way to hit it, but a deployment that needs a real
      single-use guarantee under concurrent requests MUST run Redis (for the `GETDEL`
      path) or use `DatabaseStore` instead. Do not rely on this fallback for correctness.
    """

    def __init__(self, cache_alias: str = "default") -> None:
        self._cache = caches[cache_alias]

    def get(self, key: str) -> bytes | None:
        return self._cache.get(key)

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        self._cache.set(key, value, timeout=ttl_seconds)

    def delete(self, key: str) -> None:
        self._cache.delete(key)

    def pop(self, key: str) -> bytes | None:
        redis_getdel = self._redis_getdel(key)
        if redis_getdel is not _NOT_REDIS:
            return redis_getdel

        # Fallback path -- NOT atomic. See class docstring.
        value = self._cache.get(key)
        if value is not None:
            self._cache.delete(key)
        return value

    def _redis_getdel(self, key: str) -> object:
        """Attempt the atomic `GETDEL` path. Returns `_NOT_REDIS` (since `None` is itself
        a valid "key absent" result) if the configured cache is not django-redis backed by
        a client that exposes `getdel`."""
        client_wrapper = getattr(self._cache, "client", None)
        get_client = getattr(client_wrapper, "get_client", None)
        if get_client is None:
            return _NOT_REDIS

        raw_client = get_client(write=True)
        if not hasattr(raw_client, "getdel"):
            return _NOT_REDIS

        raw_key = client_wrapper.make_key(key)
        raw_value = raw_client.getdel(raw_key)
        if raw_value is None:
            return None
        return client_wrapper.decode(raw_value)


class DatabaseStore:
    """A `Store` backed by the `StoredEntry` model.

    `pop` runs inside `transaction.atomic()` using `select_for_update()` so that, on a
    database with real row-level locking (PostgreSQL, MySQL/InnoDB), a second caller
    racing to pop the same key blocks until the first transaction commits, then simply
    finds no row -- the standard single-use-token pattern.

    The return value is additionally gated on the row count `DELETE` itself reports,
    which is what makes the guarantee hold even on a database WITHOUT real row-level
    locking (SQLite, whose `select_for_update()` is a silent no-op): two racing callers
    may both read the row before either deletes it, but a `DELETE ... WHERE pk = ...`
    statement can only ever report a match for the one execution that actually removes
    the row -- SQLite's single-writer model serializes the two `DELETE`s, and the loser's
    reports zero rows affected. `pop` returns the value it read only when its own delete
    was the one that counted; the loser gets None even though it "saw" a value moments
    earlier. See `tests/django/test_stores.py::test_database_store_pop_concurrent_race`.
    """

    def get(self, key: str) -> bytes | None:
        entry = StoredEntry.objects.filter(key=key).first()
        if entry is None or entry.is_expired():
            return None
        return bytes(entry.value)

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        expires_at = timezone.now() + datetime.timedelta(seconds=ttl_seconds)
        StoredEntry.objects.update_or_create(key=key, defaults={"value": value, "expires_at": expires_at})

    def pop(self, key: str) -> bytes | None:
        with transaction.atomic():
            entry = StoredEntry.objects.select_for_update().filter(key=key).first()
            if entry is None:
                return None
            value = bytes(entry.value)
            expired = entry.is_expired()
            deleted, _ = StoredEntry.objects.filter(pk=entry.pk).delete()

        if deleted == 0 or expired:
            return None
        return value

    def delete(self, key: str) -> None:
        StoredEntry.objects.filter(key=key).delete()


_memory_store: InMemoryStore | None = None


def _shared_memory_store() -> InMemoryStore:
    """The `memory` backend needs one dict shared across the whole process -- a fresh
    `InMemoryStore()` per call would forget everything immediately after `set()`."""
    global _memory_store
    if _memory_store is None:
        _memory_store = InMemoryStore()
    return _memory_store


def get_store() -> Store:
    """Resolve the `Store` configured by `GESUNDHEITSID["STORE_BACKEND"]`."""
    settings_ = get_settings()
    if settings_.store_backend is StoreBackend.MEMORY:
        return _shared_memory_store()
    if settings_.store_backend is StoreBackend.CACHE:
        return CacheStore(cache_alias=settings_.cache_alias)
    if settings_.store_backend is StoreBackend.DATABASE:
        return DatabaseStore()
    raise AssertionError(f"unhandled StoreBackend: {settings_.store_backend!r}")  # pragma: no cover

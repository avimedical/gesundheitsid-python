"""All three `Store` implementations against the same behavioural contract, plus a
concurrency test proving `DatabaseStore.pop` really is single-use under a race -- the
property `pop` exists as its own atomic method for in the first place (see
`gesundheitsid.storage`'s module docstring). See `stores.py`'s module docstring for
exactly what each backend's `pop` guarantees and why.

The concurrency test needs `transaction=True` (real commits, visible across connections)
and a real file-backed sqlite database (`tests/django/settings.py` points `DATABASES
["default"]["TEST"]["NAME"]` at one, with `transaction_mode: IMMEDIATE` -- see that
module's docstring for why IMMEDIATE, specifically, is required to avoid a SQLite
self-deadlock rather than a clean single-winner race).
"""

from __future__ import annotations

import threading
import time
from unittest import mock

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.db import connections

from django_gesundheitsid.stores import CacheStore, DatabaseStore, InMemoryStore, get_store

pytestmark = pytest.mark.django_db


@pytest.fixture(params=["memory", "cache", "database"])
def store(request: pytest.FixtureRequest):
    if request.param == "memory":
        return InMemoryStore()
    if request.param == "cache":
        return CacheStore(allow_non_atomic=True)
    return DatabaseStore()


def test_set_then_get_returns_the_value(store) -> None:
    store.set("key", b"value", ttl_seconds=60)
    assert store.get("key") == b"value"


def test_get_returns_none_for_a_missing_key(store) -> None:
    assert store.get("does-not-exist") is None


def test_get_returns_none_after_ttl_expires(store) -> None:
    store.set("key", b"value", ttl_seconds=0)
    time.sleep(0.05)
    assert store.get("key") is None


def test_delete_removes_a_key(store) -> None:
    store.set("key", b"value", ttl_seconds=60)
    store.delete("key")
    assert store.get("key") is None


def test_delete_on_a_missing_key_does_not_raise(store) -> None:
    store.delete("does-not-exist")  # must not raise


def test_pop_returns_the_value_once_and_none_thereafter(store) -> None:
    store.set("code", b"authorization-code", ttl_seconds=60)

    first = store.pop("code")
    second = store.pop("code")

    assert first == b"authorization-code"
    assert second is None


def test_pop_on_an_expired_key_returns_none(store) -> None:
    store.set("code", b"authorization-code", ttl_seconds=0)
    time.sleep(0.05)
    assert store.pop("code") is None


def test_pop_on_a_missing_key_returns_none(store) -> None:
    assert store.pop("does-not-exist") is None


def test_get_store_memory_returns_a_shared_singleton(settings) -> None:
    """The `memory` backend must share one dict across calls -- a fresh `InMemoryStore()`
    per `get_store()` call would forget everything written by the previous call."""
    settings.GESUNDHEITSID = {**settings.GESUNDHEITSID, "STORE_BACKEND": "memory"}

    get_store().set("shared-key", b"value", ttl_seconds=60)

    assert get_store().get("shared-key") == b"value"


def test_get_store_resolves_cache_backend(settings) -> None:
    settings.GESUNDHEITSID = {
        **settings.GESUNDHEITSID,
        "STORE_BACKEND": "cache",
        # LocMemCache here; the atomicity guard has its own tests below.
        "ALLOW_NON_ATOMIC_STORE": True,
    }
    assert isinstance(get_store(), CacheStore)


def test_get_store_resolves_database_backend(settings) -> None:
    settings.GESUNDHEITSID = {**settings.GESUNDHEITSID, "STORE_BACKEND": "database"}
    assert isinstance(get_store(), DatabaseStore)


@pytest.mark.django_db(transaction=True)
def test_database_store_pop_concurrent_race_yields_exactly_one_winner() -> None:
    """Two (here: eight, for a stronger signal) racing pops of the same key -- exactly
    one must observe the value; every other must get None, never a second copy of it."""
    store_ = DatabaseStore()
    store_.set("code", b"authorization-code", ttl_seconds=60)

    results: list[bytes | None] = []
    results_lock = threading.Lock()

    def racer() -> None:
        try:
            value = store_.pop("code")
        finally:
            # Each thread lazily opens its own Django DB connection (connections are
            # thread-local); nothing else closes it once this thread exits.
            connections.close_all()
        with results_lock:
            results.append(value)

    threads = [threading.Thread(target=racer) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners = [value for value in results if value is not None]
    assert winners == [b"authorization-code"], f"expected exactly one winner, got {winners!r}"
    assert len(results) == 8


def test_cache_store_pop_uses_getdel_when_the_backend_is_django_redis_like() -> None:
    """`CacheStore.pop` must reach for the atomic `GETDEL` path whenever the configured
    cache exposes a django-redis-shaped `.client.get_client().getdel(...)` -- exercised
    against a mock double of that interface since no real Redis server is available in
    this sandbox. The LocMemCache fallback path is exercised for real above.
    """
    fake_raw_redis = mock.Mock()
    fake_raw_redis.getdel.return_value = b"\x80encoded-payload"

    fake_client_wrapper = mock.Mock()
    fake_client_wrapper.get_client.return_value = fake_raw_redis
    fake_client_wrapper.make_key.return_value = "prefixed:key"
    fake_client_wrapper.decode.return_value = b"authorization-code"

    fake_cache = mock.Mock()
    fake_cache.client = fake_client_wrapper

    store_ = CacheStore(allow_non_atomic=True)
    store_._cache = fake_cache  # swapping the underlying cache is the point of this test

    result = store_.pop("code")

    assert result == b"authorization-code"
    fake_raw_redis.getdel.assert_called_once_with("prefixed:key")
    fake_client_wrapper.decode.assert_called_once_with(b"\x80encoded-payload")
    fake_cache.get.assert_not_called()  # the non-atomic fallback must not run


def test_cache_store_pop_falls_back_to_get_then_delete_for_a_plain_cache() -> None:
    store_ = CacheStore(allow_non_atomic=True)  # LocMemCache in tests/django/settings.py -- no `.client`
    store_.set("code", b"authorization-code", ttl_seconds=60)

    assert store_.pop("code") == b"authorization-code"
    assert store_.get("code") is None


def test_cache_store_refuses_a_non_atomic_backend_by_default() -> None:
    """A cache that cannot pop atomically is refused at construction, not tolerated silently.

    The `get()`-then-`delete()` fallback above is not a weaker single-use guarantee, it is none:
    two requests racing on one authorization code both receive it. A misconfigured CACHES alias
    is indistinguishable from a correct one until two logins happen to overlap, which is exactly
    the kind of defect that surfaces in production and nowhere else -- so it costs a startup
    error rather than a log line nobody reads.
    """
    with pytest.raises(ImproperlyConfigured, match="cannot pop atomically"):
        CacheStore()  # LocMemCache, per tests/django/settings.py


def test_cache_store_allows_a_non_atomic_backend_when_explicitly_opted_in() -> None:
    """The opt-out is explicit, so a deployment accepting the race has to say so.

    Deliberately not inferred from `DEBUG` (Django's test runner forces it off, so every cache
    test here would have had to fight the guard) nor from replica count (threads race inside one
    process just as two replicas do).
    """
    assert CacheStore(allow_non_atomic=True).pop("never-set") is None


def test_get_store_passes_the_configured_opt_out_through(settings) -> None:
    """The guard has to be reachable from configuration, or it only ever fires in unit tests."""
    settings.GESUNDHEITSID = {
        **settings.GESUNDHEITSID,
        "STORE_BACKEND": "cache",
        "ALLOW_NON_ATOMIC_STORE": False,
    }

    with pytest.raises(ImproperlyConfigured, match="cannot pop atomically"):
        get_store()

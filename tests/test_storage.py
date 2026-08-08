"""InMemoryStore: get/set/delete, TTL expiry evaluated on read, and pop's single-use
atomicity -- the reason pop exists as its own method rather than get-then-delete."""

import time

from gesundheitsid.storage import InMemoryStore


def test_set_then_get_returns_the_value() -> None:
    store = InMemoryStore()
    store.set("key", b"value", ttl_seconds=60)

    assert store.get("key") == b"value"


def test_get_returns_none_for_a_missing_key() -> None:
    store = InMemoryStore()
    assert store.get("does-not-exist") is None


def test_get_returns_none_after_ttl_expires() -> None:
    store = InMemoryStore()
    store.set("key", b"value", ttl_seconds=0)

    time.sleep(0.01)

    assert store.get("key") is None


def test_delete_removes_a_key() -> None:
    store = InMemoryStore()
    store.set("key", b"value", ttl_seconds=60)

    store.delete("key")

    assert store.get("key") is None


def test_delete_on_a_missing_key_does_not_raise() -> None:
    store = InMemoryStore()
    store.delete("does-not-exist")  # must not raise


def test_pop_returns_the_value_once_and_none_thereafter() -> None:
    store = InMemoryStore()
    store.set("code", b"authorization-code", ttl_seconds=60)

    first = store.pop("code")
    second = store.pop("code")

    assert first == b"authorization-code"
    assert second is None


def test_pop_on_an_expired_key_returns_none() -> None:
    store = InMemoryStore()
    store.set("code", b"authorization-code", ttl_seconds=0)

    time.sleep(0.01)

    assert store.pop("code") is None


def test_pop_on_a_missing_key_returns_none() -> None:
    store = InMemoryStore()
    assert store.pop("does-not-exist") is None

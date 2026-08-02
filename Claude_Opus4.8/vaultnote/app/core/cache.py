"""In-process LRU cache with TTL for hot objects (e.g. decrypted note metadata).

O(1) get/put using an OrderedDict. Thread-safe via a lock. Bounded memory by a
fixed capacity. Values are evicted on TTL expiry or when capacity is exceeded.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class LRUCache(Generic[K, V]):
    def __init__(self, capacity: int = 1024, ttl_seconds: float = 60.0,
                 clock=time.monotonic) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._ttl = ttl_seconds
        self._clock = clock
        self._store: OrderedDict[K, tuple[float, V]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: K) -> V | None:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                self.misses += 1
                return None
            expires_at, value = item
            if expires_at < self._clock():
                del self._store[key]
                self.misses += 1
                return None
            self._store.move_to_end(key)  # mark most-recently used
            self.hits += 1
            return value

    def put(self, key: K, value: V) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (self._clock() + self._ttl, value)
            while len(self._store) > self._capacity:
                self._store.popitem(last=False)  # evict least-recently used

    def invalidate(self, key: K) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

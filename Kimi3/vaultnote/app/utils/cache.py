"""
Thread-safe LRU cache with TTL for hot note decryption.

Performance: O(1) get/put via OrderedDict. Every read and mutation of the
shared mapping is guarded by a lock so the cache is safe to share across
threads (e.g. a multi-worker ASGI server sharing the process cache, or
asyncio.to_thread workers running concurrently).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


@dataclass
class _Entry:
    value: Any
    expires_at: float


class TTLRUCache:
    """Bounded LRU cache with per-item TTL (thread-safe)."""

    def __init__(self, maxsize: int = 512, ttl_seconds: int = 300) -> None:
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._data: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if time.monotonic() > entry.expires_at:
                del self._data[key]
                return None
            self._data.move_to_end(key)  # mark as recently used
            return entry.value

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = _Entry(value=value, expires_at=time.monotonic() + self._ttl)
            if len(self._data) > self._maxsize:
                self._data.popitem(last=False)  # evict least-recently-used

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._data)


# Shared cache for decrypted note payloads (short TTL for security)
note_cache = TTLRUCache(maxsize=512, ttl_seconds=120)

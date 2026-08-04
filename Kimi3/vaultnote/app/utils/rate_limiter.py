"""
Sliding-window rate limiter - O(1) per check.

Uses Redis when available; falls back to a pure-Python in-memory
implementation with the same semantics. Thread/async safe via asyncio lock.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Protocol

from app.core.config import settings

logger = logging.getLogger("vaultnote.ratelimit")


class RateLimiterBackend(Protocol):
    async def is_allowed(self, key: str, limit: int, window_seconds: int) -> bool: ...


class InMemoryRateLimiter:
    """Pure-Python sliding-window rate limiter.

    Each key maps to a deque of timestamps. On each check we pop expired
    entries from the left (O(1) amortized) and append the new one.
    """

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def is_allowed(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        async with self._lock:
            dq = self._windows[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True


class RedisRateLimiter:
    """Redis-backed sliding-window using a sorted set (ZADD/ZREMRANGEBYSCORE)."""

    def __init__(self, redis_url: str) -> None:
        import redis.asyncio as aioredis  # type: ignore
        self._r = aioredis.from_url(redis_url, decode_responses=True)

    async def is_allowed(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        pipe = self._r.pipeline()
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zcard(key)
        pipe.zadd(key, {f"{now}:{id(object())}": now})
        pipe.expire(key, window_seconds + 1)
        _, count, *_ = await pipe.execute()
        return int(count) < limit


def build_rate_limiter() -> RateLimiterBackend:
    """Factory: prefer Redis, gracefully fall back to in-memory."""
    if settings.REDIS_URL:
        try:
            return RedisRateLimiter(settings.REDIS_URL)
        except (ImportError, ValueError, TypeError) as exc:
            logger.warning("Redis rate limiter unavailable (%s); using in-memory fallback", exc)
    return InMemoryRateLimiter()


rate_limiter: RateLimiterBackend = build_rate_limiter()

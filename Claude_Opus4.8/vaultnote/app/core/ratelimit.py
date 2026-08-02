"""Sliding-window rate limiter.

Backed by Redis when ``VAULTNOTE_REDIS_URL`` is set, otherwise a pure-Python
in-memory sliding window. Both expose the same async interface and are O(1)
amortized per check. Limits are enforced per identity (user or tenant) and per
route bucket, so different endpoints get different budgets.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimit:
    """A budget of ``limit`` requests per ``window_seconds``."""

    limit: int
    window_seconds: int


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int


class InMemorySlidingWindow:
    """Pure-Python fallback. Stores timestamps per key in a bounded deque."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    async def check(self, key: str, rule: RateLimit) -> RateLimitResult:
        now = self._clock()
        window_start = now - rule.window_seconds
        with self._lock:
            dq = self._events.get(key)
            if dq is None:
                dq = deque()
                self._events[key] = dq
            while dq and dq[0] <= window_start:
                dq.popleft()
            if len(dq) >= rule.limit:
                retry_after = max(1, int(dq[0] + rule.window_seconds - now) + 1)
                return RateLimitResult(False, 0, retry_after)
            dq.append(now)
            return RateLimitResult(True, rule.limit - len(dq), 0)

    async def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class RedisSlidingWindow:
    """Redis sorted-set sliding window. Used only when redis is importable."""

    def __init__(self, redis_client, clock=time.time) -> None:
        self._redis = redis_client
        self._clock = clock

    async def check(self, key: str, rule: RateLimit) -> RateLimitResult:
        now = self._clock()
        window_start = now - rule.window_seconds
        member = f"{now}:{id(now)}"
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.expire(key, rule.window_seconds + 1)
        _, _, count, _ = await pipe.execute()
        if count > rule.limit:
            await self._redis.zrem(key, member)
            return RateLimitResult(False, 0, rule.window_seconds)
        return RateLimitResult(True, rule.limit - count, 0)

    async def reset(self, key: str) -> None:
        await self._redis.delete(key)


class RateLimiter:
    """Facade selecting a backend and applying named rules."""

    # Per-route-bucket budgets. Auth is deliberately strict (anti brute-force).
    RULES: dict[str, RateLimit] = {
        "auth": RateLimit(limit=10, window_seconds=60),
        "auth_strict": RateLimit(limit=5, window_seconds=60),
        "write": RateLimit(limit=120, window_seconds=60),
        "read": RateLimit(limit=600, window_seconds=60),
        "upload": RateLimit(limit=30, window_seconds=60),
        "export": RateLimit(limit=3, window_seconds=3600),
        "default": RateLimit(limit=300, window_seconds=60),
    }

    def __init__(self, backend) -> None:
        self._backend = backend

    @classmethod
    def create(cls, redis_url: str | None) -> "RateLimiter":
        if redis_url:
            try:  # pragma: no cover - depends on optional redis + server
                import redis.asyncio as aioredis

                client = aioredis.from_url(redis_url, decode_responses=True)
                return cls(RedisSlidingWindow(client))
            except Exception:
                pass
        return cls(InMemorySlidingWindow())

    async def check(self, *, bucket: str, identity: str) -> RateLimitResult:
        rule = self.RULES.get(bucket, self.RULES["default"])
        key = f"rl:{bucket}:{identity}"
        return await self._backend.check(key, rule)

    async def reset(self, *, bucket: str, identity: str) -> None:
        await self._backend.reset(f"rl:{bucket}:{identity}")

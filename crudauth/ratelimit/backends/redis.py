"""Redis rate-limiter backend (production). Requires ``crudauth[redis]``."""

from __future__ import annotations

import time
from typing import Any

from ..base import RateLimiterBackend
from ..constants import REDIS_KEY_PREFIX

__all__ = ["RedisBackend"]


class RedisBackend(RateLimiterBackend):
    """Async Redis counters. Overrides [increment_and_check][crudauth.ratelimit.base.RateLimiterBackend.increment_and_check] with a pipeline.

    Note:
        Pass an existing ``client=`` to share one connection pool with a
        redis-backed [RedisSessionStorage][crudauth.storage.backends.redis.RedisSessionStorage]; otherwise
        each builds its own pool to the same server.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        client: Any = None,
        prefix: str = REDIS_KEY_PREFIX,
    ):
        if client is not None:
            self.client = client
            self._owns_client = False
        else:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "Redis rate limiter requires the 'redis' package. "
                    "Install with: pip install 'crudauth[redis]'"
                ) from exc
            self.client = Redis.from_url(
                redis_url or "redis://localhost:6379/0", decode_responses=False
            )
            self._owns_client = True
        self.prefix = prefix

    def _k(self, key: str) -> str:
        return f"{self.prefix}{key}"

    async def increment(self, key: str, amount: int = 1, expiry: int | None = None) -> int:
        """Increment and arm the TTL in one transaction (``INCRBY`` + ``EXPIRE NX``).

        ``EXPIRE NX`` only sets a TTL on a key that has none, which is the
        first-touch-only contract from [RateLimiterBackend.increment][crudauth.ratelimit.base.RateLimiterBackend.increment];
        running both in one ``MULTI`` means a counter is never left without its
        TTL, and a key that somehow has none gets one on its next increment.
        """
        k = self._k(key)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.incrby(k, amount)
            if expiry is not None:
                pipe.expire(k, expiry, nx=True)
            results = await pipe.execute()
        return int(results[0])

    async def increment_and_refresh_ttl(
        self, key: str, amount: int = 1, expiry: int | None = None
    ) -> int:
        """Increment and re-arm the TTL atomically (``INCRBY`` + ``EXPIRE`` in one
        pipeline), so a concurrent attempt can't interleave between them."""
        k = self._k(key)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.incrby(k, amount)
            if expiry is not None:
                pipe.expire(k, expiry)
            results = await pipe.execute()
        return int(results[0])

    async def get_count(self, key: str) -> int | None:
        raw = await self.client.get(self._k(key))
        return int(raw) if raw is not None else None

    async def get_ttl(self, key: str) -> int:
        """Remaining TTL in seconds; ``0`` for an absent key or one with no TTL."""
        ttl = await self.client.ttl(self._k(key))
        return max(0, int(ttl))

    async def reset(self, key: str) -> None:
        await self.delete(key)

    async def delete(self, key: str) -> bool:
        return bool(await self.client.delete(self._k(key)))

    async def ping(self) -> bool:
        return bool(await self.client.ping())

    async def increment_and_check(
        self, key: str, limit: int, period: int, *, fail_open: bool = True
    ) -> tuple[int, bool, int]:
        """Fixed-window check over a window-stamped key.

        Note:
            Unlike the general ``increment`` (TTL armed first-touch only), this
            re-arms ``expire`` on every call - safe and intentional here because
            the key embeds ``window_start``, so each window is a fresh key that
            only ever lives one window. Re-arming can't extend a previous
            window's count; it just keeps the current window's key alive for its
            own duration.
        """
        now = int(time.time())
        window_start = now - (now % period)
        wkey = self._k(f"{key}:{window_start}")
        try:
            async with self.client.pipeline(transaction=True) as pipe:
                pipe.incr(wkey)
                pipe.expire(wkey, period)
                results = await pipe.execute()
            count = int(results[0])
        except Exception:
            return (0, False, 0) if fail_open else (limit + 1, True, period)
        if count <= limit:
            return count, False, 0
        return count, True, period - (now - window_start)

    async def initialize(self) -> None:
        await self.client.ping()

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

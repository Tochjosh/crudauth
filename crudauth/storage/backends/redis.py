"""Redis storage backend (production). Requires ``crudauth[redis]`` and Redis 7.0+."""

from __future__ import annotations

import json
from typing import Any, Callable

from ...constants import DEFAULT_SESSION_TTL_SECONDS, USER_INDEX_TTL_BUFFER_SECONDS
from ..base import AbstractSessionStorage, T
from ..constants import DEFAULT_REDIS_URL, DEFAULT_STORAGE_PREFIX, USER_INDEX_SUFFIX

__all__ = ["RedisSessionStorage", "redis_client_from_url"]


def redis_client_from_url(url: str | None = None) -> Any:
    """Build an async Redis client for ``url`` (localhost when omitted), guarding the optional dependency."""
    try:
        from redis.asyncio import Redis
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Redis backend requires the 'redis' package. "
            "Install with: pip install 'crudauth[redis]'"
        ) from exc
    return Redis.from_url(url or DEFAULT_REDIS_URL, decode_responses=False)


class RedisSessionStorage(AbstractSessionStorage[T]):
    """Async Redis backend with a per-user session index for fast enumeration.

    Layout:
        * ``{prefix}{session_id}`` -> serialized model (TTL = expiration)
        * ``{prefix_root}_users:{user_id}`` -> SET of session ids (TTL = the longest
          member's expiration + 1h, only ever extended)

    Note:
        No transaction spans more than one key, so the backend works on Redis
        Cluster, and a live session is never missing from its owner's index: the
        index is written before a record, an index entry is only removed with the
        record it points at, and every activity update puts the session back in the
        index and extends the index's TTL. A leftover entry points at a record that
        no longer exists; the session manager removes it the next time it reads the
        user's sessions. Needs Redis 7.0+ for ``EXPIRE NX``/``GT``.

    Note:
        Pass an existing ``client=`` to share one connection pool with other
        redis-backed components (e.g. the rate-limiter backend); otherwise each
        constructs its own pool to the same server.
    """

    def __init__(
        self,
        prefix: str = DEFAULT_STORAGE_PREFIX,
        expiration: int = DEFAULT_SESSION_TTL_SECONDS,
        redis_url: str | None = None,
        client: Any = None,
        **_: Any,
    ):
        super().__init__(prefix=prefix, expiration=expiration)
        if client is not None:
            self.client = client
            self._owns_client = False
        else:
            self.client = redis_client_from_url(redis_url)
            self._owns_client = True
        self.user_sessions_prefix = f"{prefix.rstrip(':')}{USER_INDEX_SUFFIX}"

    def _user_key(self, user_id: Any) -> str:
        return f"{self.user_sessions_prefix}{user_id}"

    @staticmethod
    def _raise_if_redis_too_old(exc: Exception) -> None:
        message = str(exc).lower()
        if "wrong number of arguments" in message or "syntax error" in message:
            raise RuntimeError(
                "crudauth's Redis session storage needs Redis 7.0 or newer (or Valkey 7.2+): "
                f"it uses EXPIRE NX and GT, and this server rejected them ({exc}). "
                "Upgrade the Redis server."
            ) from exc

    async def _index(self, user_id: Any, session_id: str, ttl: int) -> None:
        from redis.exceptions import ResponseError

        ukey = self._user_key(user_id)
        index_ttl = ttl + USER_INDEX_TTL_BUFFER_SECONDS
        try:
            async with self.client.pipeline(transaction=True) as pipe:
                pipe.sadd(ukey, session_id)
                pipe.expire(ukey, index_ttl, nx=True)
                pipe.expire(ukey, index_ttl, gt=True)
                await pipe.execute()
        except ResponseError as exc:
            self._raise_if_redis_too_old(exc)
            raise

    async def initialize(self) -> None:
        """Check the connection, failing loudly on a server older than Redis 7.0."""
        await self.client.ping()
        from redis.exceptions import ResponseError

        try:
            await self.client.expire(f"{self.prefix}redis-version-check", 1, nx=True)
        except ResponseError as exc:
            self._raise_if_redis_too_old(exc)
            raise

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def create(
        self, data: T, session_id: str | None = None, expiration: int | None = None
    ) -> str:
        sid = session_id or self.generate_session_id()
        ttl = expiration if expiration is not None else self.expiration
        payload = data.model_dump_json().encode()
        user_id = getattr(data, "user_id", None)
        if user_id is not None:
            await self._index(user_id, sid, ttl)
        await self.client.set(self.get_key(sid), payload, ex=ttl)
        return sid

    async def get(self, session_id: str, model_class: type[T]) -> T | None:
        raw = await self.client.get(self.get_key(session_id))
        if raw is None:
            return None
        return model_class.model_validate_json(raw)

    async def update(
        self,
        session_id: str,
        data: T,
        reset_expiration: bool = True,
        expiration: int | None = None,
    ) -> bool:
        """Overwrite a live session; ``False`` when it no longer exists.

        Note:
            The write is ``SET ... XX``, so a session deleted concurrently (a
            logout-all racing a request) stays deleted instead of being re-created.
        """
        key = self.get_key(session_id)
        payload = data.model_dump_json().encode()
        ttl = expiration if expiration is not None else self.expiration
        if reset_expiration:
            written = await self.client.set(key, payload, ex=ttl, xx=True)
        else:
            written = await self.client.set(key, payload, keepttl=True, xx=True)
        if not written:
            return False
        user_id = getattr(data, "user_id", None)
        if user_id is not None:
            await self._index(user_id, session_id, ttl)
        return True

    async def modify(
        self,
        session_id: str,
        model_class: type[T],
        change: Callable[[T], None],
        reset_expiration: bool = True,
        expiration: int | None = None,
    ) -> T | None:
        """Compare-and-set update: ``WATCH`` the key, apply ``change``, write in ``MULTI``.

        Note:
            A write to the key between the read and ``EXEC`` aborts the
            transaction, and the value is read and changed again. The transaction
            touches one key, so it stays within one hash slot on Redis Cluster. A
            key deleted meanwhile stays deleted and ``None`` is returned.
        """
        from redis.exceptions import WatchError

        key = self.get_key(session_id)
        ttl = expiration if expiration is not None else self.expiration
        async with self.client.pipeline(transaction=True) as pipe:
            while True:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        return None
                    data = model_class.model_validate_json(raw)
                    change(data)
                    pipe.multi()
                    if reset_expiration:
                        pipe.set(key, data.model_dump_json().encode(), ex=ttl)
                    else:
                        pipe.set(key, data.model_dump_json().encode(), keepttl=True)
                    await pipe.execute()
                    break
                except WatchError:
                    continue
        user_id = getattr(data, "user_id", None)
        if user_id is not None:
            await self._index(user_id, session_id, ttl)
        return data

    async def delete(self, session_id: str, user_id: Any = None) -> bool:
        """Delete a session and drop it from its owner's index.

        Note:
            When ``user_id`` is given (the indexed terminate paths know it), the
            owner read is skipped entirely. When it's ``None`` (e.g. logout with
            only a cookie), the record is read once to find the owner so the
            user index stays consistent. The index assumes a ``user_id``-bearing
            model; for other models nothing is read or indexed.

        Note:
            The index entry is removed only when a record was actually deleted, so
            a delete that runs between a new session's index write and its record
            write can't leave that session live but unindexed.
        """
        key = self.get_key(session_id)
        if user_id is None:
            raw = await self.client.get(key)
            if raw is not None:
                try:
                    user_id = json.loads(raw).get("user_id")
                except Exception:
                    user_id = None
        deleted = await self.client.delete(key)
        if deleted and user_id is not None:
            await self.client.srem(self._user_key(user_id), session_id)
        return bool(deleted)

    async def extend(self, session_id: str, expiration: int | None = None) -> bool:
        ttl = expiration if expiration is not None else self.expiration
        return bool(await self.client.expire(self.get_key(session_id), ttl))

    async def exists(self, session_id: str) -> bool:
        return bool(await self.client.exists(self.get_key(session_id)))

    async def set_if_absent(self, session_id: str, data: T, expiration: int | None = None) -> bool:
        """Atomic create-if-absent via ``SET key value NX EX ttl`` (single round trip)."""
        ttl = expiration if expiration is not None else self.expiration
        payload = data.model_dump_json().encode()
        result = await self.client.set(self.get_key(session_id), payload, ex=ttl, nx=True)
        return result is not None

    async def get_and_delete(self, session_id: str, model_class: type[T]) -> T | None:
        """Atomic read-and-delete via a ``MULTI/EXEC`` pipeline (portable; no GETDEL dependency).

        Note:
            Used for single-use values without a per-user index (OAuth ``state``),
            so it bypasses the user-index bookkeeping in [delete]
            [crudauth.storage.backends.redis.RedisSessionStorage.delete].
        """
        key = self.get_key(session_id)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.get(key)
            pipe.delete(key)
            raw, _ = await pipe.execute()
        if raw is None:
            return None
        return model_class.model_validate_json(raw)

    async def get_user_sessions(self, user_id: Any) -> list[str]:
        members = await self.client.smembers(self._user_key(user_id))
        return [m.decode() if isinstance(m, bytes) else m for m in members]

    async def remove_from_user_index(self, user_id: Any, session_id: str) -> None:
        """Drop an index entry whose record expired.

        Note:
            A login writes its index entry before its record, so a prune can land
            in between and unindex a session that is about to exist. Its first
            activity update puts it back.
        """
        await self.client.srem(self._user_key(user_id), session_id)

    async def scan_keys(self, match: str | None = None) -> list[str]:
        pattern = match or f"{self.prefix}*"
        keys: list[str] = []
        async for key in self.client.scan_iter(match=pattern):
            keys.append(key.decode() if isinstance(key, bytes) else key)
        return keys

    async def delete_pattern(self, pattern: str) -> int:
        count = 0
        async for key in self.client.scan_iter(match=f"{pattern}*"):
            count += await self.client.delete(key)
        return count

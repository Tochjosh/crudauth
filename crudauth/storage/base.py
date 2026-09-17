"""Abstract async storage interface shared by all backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Generic, TypeVar
from uuid import uuid4

from pydantic import BaseModel

from ..constants import DEFAULT_SESSION_TTL_SECONDS
from .constants import DEFAULT_STORAGE_PREFIX

__all__ = ["AbstractSessionStorage"]

T = TypeVar("T", bound=BaseModel)


class AbstractSessionStorage(ABC, Generic[T]):
    """Async key/value store for serializable Pydantic models with TTLs.

    Concrete backends serialize ``T`` to JSON, key it under ``{prefix}{id}`` and
    honor per-key expiration.

    Optional capabilities (duck-typed - implement if your backend can, callers
    check with ``hasattr``):

    - ``async get_user_sessions(user_id) -> list[str]`` - index sessions by user;
      unlocks multi-device limits and "sign out everywhere".
    - ``async scan_keys(match: str | None = None) -> list[str]`` - enumerate keys
      by glob; unlocks the periodic idle-session cleanup sweep. A backend without
      it simply gets no proactive sweep (per-key TTLs still expire entries).
    - ``async remove_from_user_index(user_id, session_id) -> None`` - drop an
      index entry whose record is gone. A backend with a separate per-user index
      implements it so expired sessions don't pile up there.

    Example:
        ```python
        storage = get_session_storage("redis", prefix="session:", redis_url=...)
        sid = await storage.create(SessionData(user_id=1), expiration=1800)
        data = await storage.get(sid, SessionData)
        ```
    """

    def __init__(
        self, prefix: str = DEFAULT_STORAGE_PREFIX, expiration: int = DEFAULT_SESSION_TTL_SECONDS
    ):
        self.prefix = prefix
        self.expiration = expiration

    # --- helpers -------------------------------------------------------------
    @staticmethod
    def generate_session_id() -> str:
        return str(uuid4())

    def get_key(self, session_id: str) -> str:
        return f"{self.prefix}{session_id}"

    # --- core interface ------------------------------------------------------
    @abstractmethod
    async def create(
        self, data: T, session_id: str | None = None, expiration: int | None = None
    ) -> str:
        """Store ``data`` under ``session_id`` (generated if omitted) with a TTL.

        Args:
            data: The Pydantic model to serialize.
            session_id: Key to store under; a fresh UUID if ``None``.
            expiration: TTL in seconds; the storage default if ``None``.

        Returns:
            The session id the value was stored under.
        """
        ...

    @abstractmethod
    async def get(self, session_id: str, model_class: type[T]) -> T | None:
        """Load and deserialize a value into ``model_class``, or ``None`` if absent/expired."""
        ...

    @abstractmethod
    async def update(
        self,
        session_id: str,
        data: T,
        reset_expiration: bool = True,
        expiration: int | None = None,
    ) -> bool:
        """Overwrite an existing value.

        Args:
            session_id: Key to update.
            data: New value to serialize.
            reset_expiration: If ``True``, refresh the TTL to ``expiration``.
            expiration: TTL in seconds when resetting; storage default if ``None``.

        Returns:
            ``True`` if the key existed and was updated, ``False`` otherwise.
        """
        ...

    @abstractmethod
    async def delete(self, session_id: str, user_id: Any = None) -> bool:
        """Delete a session. ``user_id``, when known by the caller, lets indexed
        backends skip re-reading the record to update their per-user index."""
        ...

    @abstractmethod
    async def extend(self, session_id: str, expiration: int | None = None) -> bool:
        """Extend a key's TTL.

        Note:
            ``expiration=None`` falls back to the *storage* default
            ([expiration][crudauth.storage.base.AbstractSessionStorage.expiration]), NOT the caller's session window - callers that
            slide a specific window (e.g. the CSRF-token TTL) must pass an
            explicit ``expiration``.
        """
        ...

    @abstractmethod
    async def exists(self, session_id: str) -> bool: ...

    # --- atomic primitives --------------------------------------------------
    async def modify(
        self,
        session_id: str,
        model_class: type[T],
        change: Callable[[T], None],
        reset_expiration: bool = True,
        expiration: int | None = None,
    ) -> T | None:
        """Apply ``change`` to a stored value and write it back without losing a concurrent write.

        Two writers that each change a different field of the same value both
        land: a write made after this call read the value makes it read again
        and reapply ``change``, so ``change`` may run more than once and must only
        set what it owns.

        Args:
            session_id: Key to modify.
            model_class: Model to deserialize into.
            change: Mutates the loaded value in place.
            reset_expiration: If ``True``, refresh the TTL to ``expiration``.
            expiration: TTL in seconds when resetting; storage default if ``None``.

        Returns:
            The value as written, or ``None`` if the key doesn't exist.

        Note:
            This default implementation is only atomic on a backend whose
            ``get``/``update`` never yield to the event loop (the in-memory
            backend). Networked backends MUST override it with a native
            compare-and-set; see
            [RedisSessionStorage][crudauth.storage.backends.redis.RedisSessionStorage].
        """
        data = await self.get(session_id, model_class)
        if data is None:
            return None
        change(data)
        if not await self.update(session_id, data, reset_expiration, expiration):
            return None
        return data

    async def set_if_absent(self, session_id: str, data: T, expiration: int | None = None) -> bool:
        """Atomically store ``data`` under ``session_id`` only if it is absent.

        Returns ``True`` if this call created the entry (the caller "won"),
        ``False`` if it already existed. This is the primitive behind a correct
        one-time-use token guard: a plain ``exists`` then ``create`` is a
        check-then-set race on a networked backend.

        Note:
            This default implementation is only atomic on a backend whose
            ``exists``/``create`` never yield to the event loop (the in-memory
            backend). Networked backends MUST override it with a native atomic
            operation (Redis ``SET NX``); see
            [RedisSessionStorage][crudauth.storage.backends.redis.RedisSessionStorage].
        """
        if await self.exists(session_id):
            return False
        await self.create(data, session_id=session_id, expiration=expiration)
        return True

    async def get_and_delete(self, session_id: str, model_class: type[T]) -> T | None:
        """Atomically read and delete an entry, returning it (or ``None``).

        Lets a single-use value (e.g. OAuth ``state``) be consumed exactly once
        even under concurrent callbacks. As with [set_if_absent]
        [crudauth.storage.base.AbstractSessionStorage.set_if_absent], the default
        is only atomic on the in-memory backend; networked backends override it.
        """
        data = await self.get(session_id, model_class)
        if data is not None:
            await self.delete(session_id)
        return data

    # --- optional capabilities ----------------------------------------------
    async def get_user_sessions(self, user_id: Any) -> list[str]:
        """Optional: session ids belonging to ``user_id``.

        Implement when the backend can index by user - unlocks multi-device
        limits and "sign out everywhere". Meaningful only for ``user_id``-bearing
        models. Raises `NotImplementedError` when unsupported.
        """
        raise NotImplementedError

    async def remove_from_user_index(self, user_id: Any, session_id: str) -> None:
        """Optional: drop ``session_id`` from ``user_id``'s index once its record is gone.

        Callers use it when an indexed id points at a missing record (an expired
        session). The default does nothing, which suits a backend that derives the
        index from the records themselves.
        """

    async def scan_keys(self, match: str | None = None) -> list[str]:
        """Optional: enumerate stored keys by glob.

        Unlocks the periodic idle-session cleanup sweep. A backend without it
        gets no proactive sweep (per-key TTLs still expire entries). Raises
        `NotImplementedError` when unsupported.
        """
        raise NotImplementedError

    async def delete_pattern(self, pattern: str) -> int:
        """Optional: delete keys by prefix. Raises `NotImplementedError`
        when unsupported. Never point this at the ``login:*`` lockout keys -
        bulk-deleting them would clear an attacker's accumulated failures."""
        raise NotImplementedError

    async def initialize(self) -> None:
        """Open connections / warm up. Default is a no-op."""

    async def close(self) -> None:
        """Release resources. Default is a no-op."""

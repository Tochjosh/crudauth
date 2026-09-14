"""[PrincipalResolver][crudauth.resolution.PrincipalResolver] - one authentication per request, shared by every gate."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, replace
from typing import Any, Callable

from fastapi import Request

from .core import AuthContext, AuthRuntime, Transport
from .exceptions import UnauthorizedException
from .principal import Principal

__all__ = ["PrincipalResolver"]

_CACHE_ATTR = "_crudauth_principals"


@dataclass
class _CachedPrincipal:
    principal: Principal
    db: Any
    csrf_enforced: bool
    activity_updated: bool


class PrincipalResolver:
    """Resolve a request's [Principal][crudauth.principal.Principal] once and share it.

    The result is cached on ``request.state`` per transport selection, so multiple
    gates in one request (``current_user()`` plus a ``KeyBy.USER`` rate limit, or
    middleware calling ``resolve_principal`` before a route) run the transport
    loop once instead of once per dependency. Gates (superuser/scopes/check) still
    run per call, on the shared principal.

    A cached principal is reused as-is on the same DB session. On another session
    the user is reloaded through that session, and the transport's
    [revalidate][crudauth.core.Transport.revalidate] applies any CSRF check or
    session activity update the earlier resolution skipped. Failed resolutions
    aren't cached, so a tampered credential still raises.
    """

    def __init__(self, runtime: AuthRuntime) -> None:
        self.runtime = runtime

    async def resolve(
        self,
        request: Request,
        db: Any,
        transports: list[Transport],
        *,
        enforce_csrf: bool = True,
        update_activity: bool = True,
    ) -> Principal | None:
        """Return the principal for ``request``, authenticating at most once per selection."""
        cache = self._cache(request)
        key = tuple(t.name for t in transports)
        cached = cache.get(key)
        if cached is None:
            ctx = self._context(request, db, enforce_csrf, update_activity)
            for transport in transports:
                principal = await transport.authenticate(request, ctx)
                if principal is not None:
                    cache[key] = _CachedPrincipal(principal, db, enforce_csrf, update_activity)
                    return principal
            return None

        if cached.db is not db:
            user = await self.runtime.repo.get_by_id(db, cached.principal.user_id)
            if user is None or not self.runtime.repo.is_active(user):
                del cache[key]
                return None
            cached.principal = replace(cached.principal, user=user)
            cached.db = db

        missing_csrf = enforce_csrf and not cached.csrf_enforced
        missing_activity = update_activity and not cached.activity_updated
        if missing_csrf or missing_activity:
            transport = next(t for t in transports if t.name == cached.principal.transport)
            ctx = self._context(request, db, missing_csrf, missing_activity)
            if not await transport.revalidate(request, cached.principal, ctx):
                del cache[key]
                return None
            cached.csrf_enforced = cached.csrf_enforced or enforce_csrf
            cached.activity_updated = cached.activity_updated or update_activity
        return cached.principal

    async def resolve_outside_dependencies(
        self, request: Request, transports: list[Transport], *, update_activity: bool = False
    ) -> Principal | None:
        """Resolve without FastAPI dependency injection, for middleware.

        Opens a DB session by calling the runtime's session dependency directly,
        never enforces CSRF, and returns ``None`` for invalid credentials.
        """
        db, close = await self._open_session()
        try:
            return await self.resolve(
                request, db, transports, enforce_csrf=False, update_activity=update_activity
            )
        except UnauthorizedException:
            return None
        finally:
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result

    def _context(
        self, request: Request, db: Any, enforce_csrf: bool, update_activity: bool
    ) -> AuthContext:
        return AuthContext(
            request=request,
            db=db,
            runtime=self.runtime,
            enforce_csrf=enforce_csrf,
            update_activity=update_activity,
        )

    @staticmethod
    def _cache(request: Request) -> dict[tuple[str, ...], _CachedPrincipal]:
        cache = getattr(request.state, _CACHE_ATTR, None)
        if cache is None:
            cache = {}
            setattr(request.state, _CACHE_ATTR, cache)
        return cache

    async def _open_session(self) -> tuple[Any, Callable[[], Any] | None]:
        dependency = self.runtime.db_dependency
        if dependency is None:
            raise RuntimeError(
                "Resolving a principal outside dependencies needs a session dependency."
            )
        provided = dependency()
        if inspect.isawaitable(provided):
            return await provided, None
        if inspect.isasyncgen(provided):
            return await anext(provided), provided.aclose
        if inspect.isgenerator(provided):
            return next(provided), provided.close
        return provided, None

"""Rate-limit dependencies: who shares a budget, the window check, and the FastAPI wiring.

This module does NOT use ``from __future__ import annotations``: the dependencies
it builds annotate parameters with ``Depends`` on runtime values, which FastAPI
must see as real objects.
"""

import inspect
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import Depends, Request, Response

from ..exceptions import RateLimitException
from ..principal import Principal
from ..utils import client_ip_key, get_client_ip, takes_two_arguments
from .base import RateLimiterBackend
from .config import KeyBy, RateLimit, RateLimitResolver
from .constants import RATE_LIMIT_NAMESPACE
from .headers import record_rate_limit_headers

__all__ = ["identity_key", "enforce_rate_limit", "limit_by_request", "limit_by_user"]

IdentityKey = Callable[[Request, Principal | None], str]
PrincipalLookup = Callable[[Request, Any], Awaitable[Principal | None]]


def identity_key(
    key: KeyBy | Callable[..., str], trusted_proxy_hops: int
) -> tuple[IdentityKey, bool]:
    """Resolve a ``key=`` other than ``KeyBy.USER`` into the function naming a request's budget.

    Returns:
        ``(identity, reads_principal)``: ``identity(request, principal)`` names the
        budget, and ``reads_principal`` says whether it needs the principal.

    Raises:
        ValueError: If ``key`` is neither a supported ``KeyBy`` nor a callable.
    """
    if key is KeyBy.IP:
        return (
            lambda request, principal: client_ip_key(get_client_ip(request, trusted_proxy_hops))
        ), False
    if key is KeyBy.USER_OR_IP:

        def by_user_or_ip(request: Request, principal: Principal | None) -> str:
            if principal is not None:
                return f"user:{principal.user_id}"
            return f"ip:{client_ip_key(get_client_ip(request, trusted_proxy_hops))}"

        return by_user_or_ip, True
    if callable(key):
        callback = key
        if takes_two_arguments(callback):
            return (lambda request, principal: callback(request, principal)), True
        return (lambda request, principal: callback(request)), False
    raise ValueError(f"Unsupported rate limit key: {key!r}")


async def enforce_rate_limit(
    backend: RateLimiterBackend | None,
    request: Request,
    response: Response,
    *,
    action: str,
    identity: str,
    limit: RateLimit | RateLimitResolver,
    principal: Principal | None = None,
) -> None:
    """Count the request against ``action`` for ``identity`` and raise 429 when it's over.

    Writes ``X-RateLimit-Limit`` / ``X-RateLimit-Remaining``. A resolver returning
    ``None``, a disabled limit, or no backend lets the request through.

    Note:
        Headers set on the injected ``Response`` only reach the client when the
        route returns normally. The limiter's own ``429`` carries them on the
        [RateLimitException][crudauth.exceptions.RateLimitException]; for any
        other error response they're also recorded on the request, where
        [RateLimitHeadersMiddleware][crudauth.ratelimit.RateLimitHeadersMiddleware]
        picks them up.
    """
    effective = limit(request, principal) if callable(limit) else limit
    if inspect.isawaitable(effective):
        effective = await effective
    if effective is None or backend is None or effective.disabled:
        return
    count, limited, retry_after = await backend.increment_and_check(
        f"{RATE_LIMIT_NAMESPACE}:{action}:{identity}",
        effective.times,
        effective.seconds,
        fail_open=True,
    )
    headers = {
        "X-RateLimit-Limit": str(effective.times),
        "X-RateLimit-Remaining": str(max(0, effective.times - count)),
    }
    if limited:
        headers["X-RateLimit-Remaining"] = "0"
    response.headers.update(record_rate_limit_headers(request, headers))
    if limited:
        raise RateLimitException(
            "Too many requests. Try again later.",
            retry_after=retry_after,
            headers=headers,
        )


def limit_by_request(
    backend: RateLimiterBackend | None,
    *,
    action: str,
    limit: RateLimit | RateLimitResolver,
    key: KeyBy | Callable[..., str],
    trusted_proxy_hops: int,
    session: Callable[..., Any],
    principal: PrincipalLookup,
) -> Callable[..., Awaitable[None]]:
    """A dependency limiting by ``key``, resolving the principal only when the key or limit reads it."""
    identity, reads_principal = identity_key(key, trusted_proxy_hops)

    if not (reads_principal or callable(limit)):

        async def anonymous(request: Request, response: Response) -> None:
            await enforce_rate_limit(
                backend,
                request,
                response,
                action=action,
                identity=identity(request, None),
                limit=limit,
            )

        return anonymous

    async def identified(
        request: Request, response: Response, db: Annotated[Any, Depends(session)]
    ) -> None:
        caller = await principal(request, db)
        await enforce_rate_limit(
            backend,
            request,
            response,
            action=action,
            identity=identity(request, caller),
            limit=limit,
            principal=caller,
        )

    return identified


def limit_by_user(
    backend: RateLimiterBackend | None,
    *,
    action: str,
    limit: RateLimit | RateLimitResolver,
    current_user: Callable[..., Any],
) -> Callable[..., Awaitable[None]]:
    """A dependency limiting each authenticated user, rejecting anonymous callers through ``current_user``."""

    async def by_user(
        request: Request,
        response: Response,
        user: Annotated[Principal, Depends(current_user)],
    ) -> None:
        await enforce_rate_limit(
            backend,
            request,
            response,
            action=action,
            identity=str(user.user_id),
            limit=limit,
            principal=user,
        )

    return by_user

"""Rate-limit headers on every response a limiter counted, error responses included.

``rate_limit()`` dependencies write ``X-RateLimit-Limit`` and ``X-RateLimit-Remaining``
onto the ``Response`` FastAPI injects, which only reaches the client when the route
returns normally. When anything after the limiter raises - an auth dependency's 401,
a 404 from the route, a validation error - FastAPI builds the response from the
exception and those headers are lost, although the request was counted. The limiter
also records them on the request, and
[RateLimitHeadersMiddleware][crudauth.ratelimit.RateLimitHeadersMiddleware]
copies them onto whatever response leaves the app.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .constants import RATE_LIMIT_HEADERS_STATE

__all__ = ["RateLimitHeadersMiddleware", "record_rate_limit_headers"]

REMAINING = "X-RateLimit-Remaining"


def record_rate_limit_headers(request: Request, headers: dict[str, str]) -> dict[str, str]:
    """Remember the headers a limiter computed for this request, and return the ones to send.

    A request counted by more than one limiter keeps the budget closest to running
    out, since that's the one the client will hit first.
    """
    recorded: dict[str, str] | None = getattr(request.state, RATE_LIMIT_HEADERS_STATE, None)
    if recorded is not None and int(recorded[REMAINING]) <= int(headers[REMAINING]):
        return recorded
    setattr(request.state, RATE_LIMIT_HEADERS_STATE, dict(headers))
    return headers


class RateLimitHeadersMiddleware:
    """Copy the recorded rate-limit headers onto every response that carries none.

    Opt-in: add it to the app to have ``401``, ``404`` and ``422`` responses report
    the budget they spent. A response that already carries the headers - a route
    that returned normally, or the limiter's own ``429`` - is left as it is, and a
    request no limiter counted gets nothing.

    Example:
        ```python
        from crudauth.ratelimit import RateLimitHeadersMiddleware

        app.add_middleware(RateLimitHeadersMiddleware)
        ```
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                recorded = scope.get("state", {}).get(RATE_LIMIT_HEADERS_STATE)
                if recorded:
                    headers = MutableHeaders(scope=message)
                    for name, value in recorded.items():
                        if name not in headers:
                            headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)

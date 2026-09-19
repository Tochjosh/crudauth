"""Rate-limit headers on responses a limiter counted but something after it refused."""

from __future__ import annotations

import httpx
from fastapi import Depends, FastAPI, HTTPException

from crudauth import CookieConfig, CRUDAuth, Principal, SessionTransport
from crudauth.ratelimit import MemoryRateLimiterBackend, RateLimit, RateLimitHeadersMiddleware

LIMIT = "X-RateLimit-Limit"
REMAINING = "X-RateLimit-Remaining"


class BlockingBackend(MemoryRateLimiterBackend):
    """Refuses every request while reporting a count under the limit."""

    async def increment_and_check(self, key, limit, period, *, fail_open=True):
        return 1, True, 30


def _auth(get_session, UserModel, **kwargs) -> CRUDAuth:
    return CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        warn_on_memory_backend=False,
        **kwargs,
    )


def _app(auth: CRUDAuth, *, middleware: bool) -> FastAPI:
    app = FastAPI()
    if middleware:
        app.add_middleware(RateLimitHeadersMiddleware)
    limited = [Depends(auth.rate_limit("api", RateLimit(3, 100)))]

    @app.get("/me", dependencies=limited)
    async def me(_: Principal = Depends(auth.current_user())) -> dict:
        return {"ok": True}

    @app.get("/items/{item_id}", dependencies=limited)
    async def item(item_id: int) -> dict:
        raise HTTPException(status_code=404, detail="Not found")

    @app.get("/ok", dependencies=limited)
    async def ok() -> dict:
        return {"ok": True}

    @app.get(
        "/both",
        dependencies=[
            Depends(auth.rate_limit("wide", RateLimit(10, 100))),
            Depends(auth.rate_limit("narrow", RateLimit(2, 100))),
            Depends(auth.rate_limit("wider", RateLimit(20, 100))),
        ],
    )
    async def both(fail: bool = True) -> dict:
        if fail:
            raise HTTPException(status_code=404, detail="Not found")
        return {"ok": True}

    @app.get("/open")
    async def open_route() -> dict:
        raise HTTPException(status_code=404, detail="Not found")

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_without_the_middleware_a_refused_request_has_no_headers(
    get_session, UserModel
) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=False)) as client:
        response = await client.get("/me")
    await auth.shutdown()

    assert response.status_code == 401
    assert LIMIT not in response.headers


async def test_a_401_after_the_limiter_reports_the_budget_it_spent(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=True)) as client:
        responses = [await client.get("/me") for _ in range(4)]
    await auth.shutdown()

    assert [r.status_code for r in responses] == [401, 401, 401, 429]
    assert [r.headers.get(REMAINING) for r in responses] == ["2", "1", "0", "0"]
    assert all(r.headers.get(LIMIT) == "3" for r in responses)
    assert "Retry-After" in responses[-1].headers


async def test_a_404_from_the_route_reports_the_budget(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=True)) as client:
        response = await client.get("/items/1")
    await auth.shutdown()

    assert response.status_code == 404
    assert response.headers[LIMIT] == "3"
    assert response.headers[REMAINING] == "2"


async def test_a_validation_error_reports_the_budget(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=True)) as client:
        response = await client.get("/items/not-a-number")
    await auth.shutdown()

    assert response.status_code == 422
    assert response.headers[REMAINING] == "2"


async def test_an_answered_request_carries_each_header_once(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=True)) as client:
        response = await client.get("/ok")
    await auth.shutdown()

    assert response.status_code == 200
    assert response.headers.get_list(LIMIT) == ["3"]
    assert response.headers.get_list(REMAINING) == ["2"]


async def test_the_limiter_closest_to_running_out_is_reported(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=True)) as client:
        response = await client.get("/both")
    await auth.shutdown()

    assert response.status_code == 404
    assert response.headers[LIMIT] == "2"
    assert response.headers[REMAINING] == "1"


async def test_an_answered_request_reports_the_limiter_closest_to_running_out(
    get_session, UserModel
) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=False)) as client:
        response = await client.get("/both", params={"fail": False})
    await auth.shutdown()

    assert response.status_code == 200
    assert response.headers.get_list(LIMIT) == ["2"]
    assert response.headers.get_list(REMAINING) == ["1"]


async def test_a_request_no_limiter_counted_gets_no_headers(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    async with _client(_app(auth, middleware=True)) as client:
        response = await client.get("/open")
    await auth.shutdown()

    assert response.status_code == 404
    assert LIMIT not in response.headers
    assert REMAINING not in response.headers


async def test_a_limited_request_reports_nothing_remaining_whatever_the_count(
    get_session, UserModel
) -> None:
    auth = _auth(get_session, UserModel, rate_limiter=BlockingBackend())
    await auth.initialize()
    async with _client(_app(auth, middleware=True)) as client:
        response = await client.get("/ok")
    await auth.shutdown()

    assert response.status_code == 429
    assert response.headers.get_list(REMAINING) == ["0"]

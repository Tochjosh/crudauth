"""Public request-level principal resolution."""

from __future__ import annotations

import httpx
from fastapi import Depends, FastAPI, Request

from crudauth import CookieConfig, CRUDAuth, Principal, SessionTransport
from crudauth.core import AuthContext, Transport
from crudauth.exceptions import UnauthorizedException

SECRET = "test-secret-key-0123456789-0123456789"


async def test_middleware_resolution_is_cached_and_does_not_bypass_csrf(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.middleware("http")
    async def resolve(request: Request, call_next):
        request.state.middleware_principal = await auth.resolve_principal(request)
        return await call_next(request)

    @app.post("/protected")
    async def protected(user: Principal = Depends(auth.current_user())):
        return {"via": user.transport}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
        csrf = login.json()["csrf_token"]
        assert (await client.post("/protected")).status_code == 403
        response = await client.post("/protected", headers={"X-CSRF-Token": csrf})
        assert response.json() == {"via": "session"}
    await auth.shutdown()


async def test_invalid_credentials_are_anonymous(get_session, UserModel):
    auth = CRUDAuth(session=get_session, user_model=UserModel, SECRET_KEY=SECRET)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Bearer bad")],
        }
    )
    assert await auth.resolve_principal(request) is None


class CountingTransport(Transport):
    name = "counting"

    def __init__(self):
        self.calls = 0

    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        self.calls += 1
        if request.headers.get("x-auth") != "yes":
            raise UnauthorizedException("invalid")
        return Principal(user_id=1, transport=self.name)


async def test_public_resolution_shares_cache_with_dependency(get_session, UserModel):
    transport = CountingTransport()
    auth = CRUDAuth(
        session=get_session, user_model=UserModel, SECRET_KEY=SECRET, transports=[transport]
    )
    app = FastAPI()

    @app.middleware("http")
    async def resolve(request: Request, call_next):
        await auth.resolve_principal(request)
        return await call_next(request)

    @app.get("/")
    async def route(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Auth": "yes"})
        assert response.json() == {"id": 1}
    await auth.shutdown()
    assert transport.calls == 1

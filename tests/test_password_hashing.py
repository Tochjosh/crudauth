"""Password hashing on the request path: off the event loop, timing-equal, Unicode-normalized."""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import asynccontextmanager
from typing import Any

import bcrypt
import httpx
from fastapi import Depends, FastAPI, Request
from starlette.requests import Request as StarletteRequest

from crudauth import (
    CookieConfig,
    CRUDAuth,
    EmailConfig,
    EmailSender,
    Principal,
    SessionTransport,
    SudoConfig,
)
from crudauth.utils import _bcrypt_input, make_unusable_password, verify_password

SECRET = "test-secret-key-0123456789-0123456789"
PRECOMPOSED = "caf\u00e9-secret"
COMBINING = "cafe\u0301-secret"


class _CapturingSender(EmailSender):
    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}

    async def send(self, *, to, subject, body, kind, context):
        self.tokens[kind] = body.split("token=")[-1]


def _build(get_session, UserModel, **kw: Any):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        **kw,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return app, auth


@asynccontextmanager
async def _client(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


async def _create_user(auth, sessionmaker, username: str, hashed_password: str) -> None:
    async with sessionmaker() as db:
        await auth.repo.create(
            db,
            {
                "email": f"{username}@x.com",
                "username": username,
                "hashed_password": hashed_password,
            },
        )


async def _stored_hash(auth, sessionmaker, username: str) -> str:
    async with sessionmaker() as db:
        user = await auth.repo.get_by_username(db, username)
        return auth.repo.get(user, "hashed_password")


async def _login_seconds(c, username: str, password: str) -> float:
    start = time.perf_counter()
    r = await c.post("/login", data={"username": username, "password": password})
    assert r.status_code == 401
    return time.perf_counter() - start


async def test_login_keeps_the_event_loop_responsive(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        blocking = await _login_seconds(c, "a", "wrong-password")
        login = asyncio.ensure_future(
            c.post("/login", data={"username": "a", "password": "wrong-password"})
        )
        longest_gap = 0.0
        last = time.perf_counter()
        while not login.done():
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            longest_gap = max(longest_gap, now - last)
            last = now
        assert login.result().status_code == 401
        assert longest_gap < blocking / 2
    await auth.shutdown()


async def test_oauth_only_account_login_costs_a_full_verification(
    get_session, UserModel, sessionmaker
) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    await _create_user(auth, sessionmaker, "oauth", make_unusable_password())
    async with _client(app) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        await _login_seconds(c, "nobody", "wrong-password")
        real = await _login_seconds(c, "a", "wrong-password")
        assert await _login_seconds(c, "oauth", "wrong-password") > real / 2
    await auth.shutdown()


async def test_password_verifies_across_unicode_forms(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": PRECOMPOSED}
        )
        await c.post("/register", json={"email": "b@x.com", "username": "b", "password": COMBINING})
        r = await c.post("/login", data={"username": "a", "password": COMBINING})
        assert r.status_code == 200
        r = await c.post("/login", data={"username": "b", "password": PRECOMPOSED})
        assert r.status_code == 200
    await auth.shutdown()


async def test_login_rehashes_a_hash_from_before_normalization(
    get_session, UserModel, sessionmaker
) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    legacy = bcrypt.hashpw(_bcrypt_input(COMBINING), bcrypt.gensalt()).decode()
    await _create_user(auth, sessionmaker, "legacy", legacy)
    async with _client(app) as c:
        r = await c.post("/login", data={"username": "legacy", "password": COMBINING})
        assert r.status_code == 200
        rehashed = await _stored_hash(auth, sessionmaker, "legacy")
        assert rehashed != legacy
        assert bcrypt.checkpw(_bcrypt_input(PRECOMPOSED), rehashed.encode())
        assert verify_password(COMBINING, rehashed)
        r = await c.post("/login", data={"username": "legacy", "password": PRECOMPOSED})
        assert r.status_code == 200
        assert await _stored_hash(auth, sessionmaker, "legacy") == rehashed
    await auth.shutdown()


async def test_failed_login_leaves_a_hash_from_before_normalization_alone(
    get_session, UserModel, sessionmaker
) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    legacy = bcrypt.hashpw(_bcrypt_input(COMBINING), bcrypt.gensalt()).decode()
    await _create_user(auth, sessionmaker, "legacy", legacy)
    async with _client(app) as c:
        await _login_seconds(c, "legacy", "wrong-password")
        assert await _stored_hash(auth, sessionmaker, "legacy") == legacy
    await auth.shutdown()


async def test_no_request_path_hashes_or_verifies_on_the_event_loop(
    get_session, UserModel, sessionmaker, monkeypatch
) -> None:
    sender = _CapturingSender()
    app, auth = _build(
        get_session,
        UserModel,
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
        sudo=SudoConfig(),
    )
    sudo = auth.sudo
    assert sudo is not None

    @app.post("/sudo")
    async def elevate(request: Request, principal: Principal = Depends(auth.current_user())):
        await sudo.elevate(principal, "pw123456", request=request)

    loop_thread = threading.get_ident()
    on_loop: list[str] = []

    def off_loop(name: str, original: Any) -> Any:
        def wrapper(*args: Any) -> Any:
            if threading.get_ident() == loop_thread:
                on_loop.append(name)
            return original(*args)

        return wrapper

    await auth.initialize()
    await _create_user(auth, sessionmaker, "oauth", make_unusable_password())
    async with sessionmaker() as db:
        oauth_user = await auth.repo.get_by_username(db, "oauth")
    oauth_request = StarletteRequest(
        {"type": "http", "method": "GET", "headers": [], "client": ("1.2.3.4", 1234)}
    )
    oauth_sid, oauth_csrf = await auth.sessions.create_session(
        oauth_request, user_id=auth.repo.user_id(oauth_user)
    )
    monkeypatch.setattr(bcrypt, "hashpw", off_loop("hashpw", bcrypt.hashpw))
    monkeypatch.setattr(bcrypt, "checkpw", off_loop("checkpw", bcrypt.checkpw))
    async with _client(app) as c:
        r = await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        assert r.status_code == 202
        r = await c.post("/login", data={"username": "nobody", "password": "x"})
        assert r.status_code == 401
        r = await c.post("/login", data={"username": "a", "password": "pw123456"})
        headers = {"X-CSRF-Token": r.json()["csrf_token"]}
        r = await c.post("/sudo", headers=headers)
        assert r.status_code == 200
        r = await c.post(
            "/email/change-request",
            json={"new_email": "a2@x.com", "password": "pw123456"},
            headers=headers,
        )
        assert r.status_code == 200
        r = await c.post(
            "/change-password",
            json={"current_password": "pw123456", "new_password": "pw654321"},
            headers=headers,
        )
        assert r.status_code == 200
        await c.post("/password/reset-request", json={"email": "a@x.com"})
        r = await c.post(
            "/password/reset-confirm",
            json={"token": sender.tokens["reset_password"], "new_password": "pw999999"},
        )
        assert r.status_code == 200
        c.cookies.set("session_id", oauth_sid)
        r = await c.post(
            "/set-password", json={"new_password": "pw123456"}, headers={"X-CSRF-Token": oauth_csrf}
        )
        assert r.status_code == 200
    assert on_loop == []
    await auth.shutdown()

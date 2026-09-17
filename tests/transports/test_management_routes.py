"""Opt-in session/CSRF management routes: /logout-all, /sessions, DELETE /sessions/{id}, /csrf/refresh.

Mounted only by SessionTransport(management_routes=True). All run behind a session principal except
/csrf/refresh (the recovery path, which resolves the session cookie directly)."""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from crudauth import CRUDAuth, CookieConfig, SessionTransport

SECRET = "test-secret-key-0123456789-0123456789"


def _build(get_session, UserModel, *, management_routes=True, csrf=True):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[
            SessionTransport(
                cookies=CookieConfig(secure=False), management_routes=management_routes, csrf=csrf
            )
        ],
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


async def _register_login(c, username="alice", email=None):
    email = email or f"{username}@x.com"
    await c.post("/register", json={"email": email, "username": username, "password": "pw123456"})
    r = await c.post("/login", data={"username": username, "password": "pw123456"})
    return r.json()["csrf_token"]


async def test_routes_gated_off_by_default(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel, management_routes=False)
    await auth.initialize()
    async with _client(app) as c:
        await _register_login(c)
        resp = await c.get("/sessions")
        assert resp.status_code == 404  # not mounted
    await auth.shutdown()


async def test_logout_all_revokes_and_clears(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        csrf = await _register_login(c)
        r = await c.post("/logout-all", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        assert r.json()["revoked"] >= 1
        resp = await c.get("/me")
        assert resp.status_code == 401  # cookie cleared, session gone
    await auth.shutdown()


async def test_logout_all_keep_current(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as a, _client(app) as b:
        csrf_a = await _register_login(a)
        await _register_login(b)  # second session for the same user
        r = await a.post("/logout-all?keep_current=true", headers={"X-CSRF-Token": csrf_a})
        assert r.status_code == 200 and r.json()["revoked"] == 1  # revoked B, kept A
        resp = await a.get("/me")
        assert resp.status_code == 200  # caller's session survives
        resp = await b.get("/me")
        assert resp.status_code == 401  # the other session is gone
    await auth.shutdown()


async def test_sessions_list_shape_and_current_flag(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        await _register_login(c)
        rows = (await c.get("/sessions")).json()
        assert len(rows) == 1
        s = rows[0]
        assert set(s) >= {"id", "device", "ip", "created_at", "last_activity", "current"}
        assert s["current"] is True
    await auth.shutdown()


async def test_delete_own_other_unknown_and_cross_user(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as a, _client(app) as b, _client(app) as other:
        csrf_a = await _register_login(a, "alice")
        await _register_login(b, "alice")  # alice's 2nd session
        csrf_other = await _register_login(other, "bob")  # different user

        sessions = (await a.get("/sessions")).json()
        b_id = next(s["id"] for s in sessions if not s["current"])
        a_id = next(s["id"] for s in sessions if s["current"])

        # revoke alice's other session (B)
        r = await a.delete(f"/sessions/{b_id}", headers={"X-CSRF-Token": csrf_a})
        assert r.status_code == 200
        resp = await b.get("/me")
        assert resp.status_code == 401

        # unknown id -> 404
        resp = await a.delete("/sessions/nope", headers={"X-CSRF-Token": csrf_a})
        assert resp.status_code == 404

        # another user's session id -> 404 (ownership check, no leak)
        resp = await other.delete(f"/sessions/{a_id}", headers={"X-CSRF-Token": csrf_other})
        assert resp.status_code == 404
        resp = await a.get("/me")
        assert resp.status_code == 200  # untouched

        # revoke own current session -> 200 + cookie cleared
        r = await a.delete(f"/sessions/{a_id}", headers={"X-CSRF-Token": csrf_a})
        assert r.status_code == 200
        resp = await a.get("/me")
        assert resp.status_code == 401
    await auth.shutdown()


async def test_csrf_refresh_self_heal_and_rotate(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    csrf_name = auth.sessions.csrf_cookie_name
    async with _client(app) as c:
        csrf = await _register_login(c)
        # valid cookie -> same token, no rotation (self-heal)
        r = await c.post("/csrf/refresh")
        assert r.status_code == 200 and r.json()["csrf_token"] == csrf

        # drop the csrf cookie -> new token minted + Set-Cookie
        del c.cookies[csrf_name]
        r = await c.post("/csrf/refresh")
        assert r.status_code == 200
        new = r.json()["csrf_token"]
        assert new and new != ""
        assert csrf_name in r.headers.get("set-cookie", "")
    await auth.shutdown()


async def test_csrf_refresh_no_session_401(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        resp = await c.post("/csrf/refresh")
        assert resp.status_code == 401  # no session cookie
    await auth.shutdown()


async def test_csrf_refresh_disabled_400(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel, csrf=False)
    await auth.initialize()
    async with _client(app) as c:
        await _register_login(c)
        resp = await c.post("/csrf/refresh")
        assert resp.status_code == 400  # CSRF disabled
    await auth.shutdown()

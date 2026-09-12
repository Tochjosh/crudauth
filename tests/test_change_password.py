"""POST /change-password: in-session change with the current password, evicting other credentials.

Unconditional (sibling of /set-password). Re-auth is the current password; a successful change bumps
token_version and revokes the user's other sessions, keeping the current one."""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from crudauth import AuthHooks, CookieConfig, CRUDAuth, PasswordPolicy, SessionTransport
from crudauth.repository import UserRepository
from crudauth.utils import make_unusable_password

SECRET = "test-secret-key-0123456789-0123456789"


def _build(get_session, UserModel, hooks=None, password_policy=None):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        hooks=hooks or AuthHooks(),
        password_policy=password_policy,
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


async def _register_login(c, password="pw123456"):
    await c.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": password}
    )
    r = await c.post("/login", data={"username": "alice", "password": password})
    return r.json()["csrf_token"]


async def test_wrong_current_password_401(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        csrf = await _register_login(c)
        r = await c.post(
            "/change-password",
            headers={"X-CSRF-Token": csrf},
            json={"current_password": "not-it", "new_password": "new-strong-1"},
        )
        assert r.status_code == 401
    await auth.shutdown()


async def test_configured_policy_rejects_change(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel, password_policy=PasswordPolicy(min_length=12))
    await auth.initialize()
    async with _client(app) as c:
        csrf = await _register_login(c, "pw1234567890")
        r = await c.post(
            "/change-password",
            headers={"X-CSRF-Token": csrf},
            json={"current_password": "pw1234567890", "new_password": "short"},
        )
        assert r.status_code == 422
    await auth.shutdown()


async def test_unusable_password_400(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        csrf = await _register_login(c)
        repo = UserRepository(UserModel)
        async with sessionmaker() as db:  # flip the stored hash to unusable (OAuth-only shape)
            user = await repo.get_by_email(db, "a@x.com")
            await repo.update(db, user, {"hashed_password": make_unusable_password()})
        r = await c.post(
            "/change-password",
            headers={"X-CSRF-Token": csrf},
            json={"current_password": "pw123456", "new_password": "new-strong-1"},
        )
        assert r.status_code == 400  # points at /set-password
    await auth.shutdown()


async def test_change_password_success_rotates_evicts_and_fires_hook(
    get_session, UserModel, sessionmaker
) -> None:
    fired: list[dict] = []
    hooks = AuthHooks(on_after_password_changed=lambda user, **kw: fired.append(user))
    app, auth = _build(get_session, UserModel, hooks=hooks)
    await auth.initialize()
    async with _client(app) as a, _client(app) as b:
        csrf_a = await _register_login(a)
        # second session for the same user (its own jar)
        r = await b.post("/login", data={"username": "alice", "password": "pw123456"})
        assert r.status_code == 200

        r = await a.post(
            "/change-password",
            headers={"X-CSRF-Token": csrf_a},
            json={"current_password": "pw123456", "new_password": "new-strong-1"},
        )
        assert r.status_code == 200

        assert len(fired) == 1  # on_after_password_changed fired once
        resp = await b.get("/me")
        assert resp.status_code == 401  # other session evicted
        resp = await a.get("/me")
        assert resp.status_code == 200  # caller's session kept

        repo = UserRepository(UserModel)
        async with sessionmaker() as db:
            user = await repo.get_by_email(db, "a@x.com")
            assert repo.token_version(user) == 1  # bumped (evicts bearer tokens)

    # the hash actually rotated: new password logs in, old does not
    async with _client(app) as fresh:
        resp = await fresh.post("/login", data={"username": "alice", "password": "new-strong-1"})
        assert resp.status_code == 200
        resp = await fresh.post("/login", data={"username": "alice", "password": "pw123456"})
        assert resp.status_code == 401
    await auth.shutdown()


async def test_change_password_requires_csrf_on_session(get_session, UserModel) -> None:
    # CSRF is auto-enforced on the session path (the spec's "free CSRF" claim):
    # a mutation behind current_user() without the X-CSRF-Token header is a 403.
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        await _register_login(c)  # session + csrf cookie in the jar; header deliberately omitted
        r = await c.post(
            "/change-password",
            json={"current_password": "pw123456", "new_password": "new-strong-1"},
        )
        assert r.status_code == 403
    await auth.shutdown()


async def test_change_password_rate_limited(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with _client(app) as c:
        csrf = await _register_login(c)
        body = {"current_password": "wrong", "new_password": "new-strong-1"}
        for _ in range(5):  # the change_password default is 5/hour, keyed by user
            await c.post("/change-password", headers={"X-CSRF-Token": csrf}, json=body)
        r = await c.post("/change-password", headers={"X-CSRF-Token": csrf}, json=body)
        assert r.status_code == 429
    await auth.shutdown()

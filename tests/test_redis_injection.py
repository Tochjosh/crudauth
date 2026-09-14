"""Redis configuration: one CRUDAuth-level default, per-part overrides, caller-owned clients."""

from __future__ import annotations

import logging
from typing import Any

import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI
from redis.crc import key_slot

from crudauth import (
    CookieConfig,
    CRUDAuth,
    EmailConfig,
    EmailSender,
    OAuthCredentials,
    SessionTransport,
)
from crudauth.ratelimit import redis_rate_limiter
from crudauth.storage import MemorySessionStorage, RedisSessionStorage

SECRET = "test-secret-key-0123456789-0123456789"


class CapturingSender(EmailSender):
    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}

    async def send(self, *, to, subject, body, kind, context):
        self.tokens[kind] = body.split("token=")[-1]


def _email(sender: EmailSender | None = None) -> EmailConfig:
    return EmailConfig(sender=sender or CapturingSender(), frontend_url="https://app.example.com")


def _token_store(auth: CRUDAuth) -> Any:
    assert auth.emails is not None
    return auth.emails.token_store


def _connection(backend: Any) -> tuple[str, int, int]:
    kwargs = backend.client.connection_pool.connection_kwargs
    return kwargs["host"], kwargs["port"], kwargs["db"]


def _recording(closed: list[str], name: str):
    async def aclose() -> None:
        closed.append(name)

    return aclose


async def test_one_redis_client_backs_every_store(get_session, UserModel, caplog) -> None:
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    sender = CapturingSender()
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        auth = CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            redis_client=client,
            email=_email(sender),
            oauth={"google": OAuthCredentials(client_id="id", client_secret="secret")},
            redirect_base_url="http://test",
        )
    app = FastAPI()
    app.include_router(auth.router)

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        login = await c.post("/login", data={"username": "alice", "password": "pw123456"})
        me = await c.get("/me")
        verified = await c.post(
            "/email/verify-confirm", json={"token": sender.tokens["verify_email"]}
        )
        authorize = await c.get("/oauth/google/authorize")
    await auth.shutdown()

    assert (login.status_code, me.status_code, verified.status_code) == (200, 200, 200)
    assert authorize.status_code == 307
    prefixes = {key.split(":")[0] for key in map(str, await client.keys("*"))}
    assert {"session", "csrf", "used_token", "oauth_state", "crudauth"} <= prefixes
    assert "in-memory backend" not in caplog.text
    assert await client.ping() is True


def test_redis_url_opens_one_client_for_every_store(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        redis_url="redis://auth-redis.internal:6380/5",
        email=_email(),
        warn_on_memory_backend=False,
    )
    parts = [
        auth.sessions.storage,
        auth.sessions.csrf_storage,
        _token_store(auth),
        auth.runtime.rate_limiter,
    ]

    assert {_connection(part) for part in parts} == {("auth-redis.internal", 6380, 5)}
    assert len({id(getattr(part, "client")) for part in parts}) == 1


def test_parts_configured_directly_override_the_crudauth_default(get_session, UserModel) -> None:
    shared = fakeredis.aioredis.FakeRedis()
    sessions = fakeredis.aioredis.FakeRedis()
    limiter = fakeredis.aioredis.FakeRedis()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        redis_client=shared,
        transports=[SessionTransport(redis_client=sessions)],
        rate_limiter=redis_rate_limiter(client=limiter),
        email=_email(),
        warn_on_memory_backend=False,
    )

    assert auth.sessions.storage.client is sessions
    assert auth.sessions.csrf_storage.client is sessions
    assert getattr(auth.runtime.rate_limiter, "client") is limiter
    assert _token_store(auth).client is shared


def test_redis_session_transport_without_a_connection_uses_the_crudauth_one(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        redis_url="redis://auth-redis.internal:6379/2",
        transports=[SessionTransport(backend="redis")],
        warn_on_memory_backend=False,
    )

    assert _connection(auth.sessions.storage) == ("auth-redis.internal", 6379, 2)


def test_redis_session_transport_without_any_connection_uses_one_localhost_client(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(backend="redis")],
        warn_on_memory_backend=False,
    )

    assert _connection(auth.sessions.storage) == ("localhost", 6379, 0)
    assert auth.sessions.csrf_storage.client is auth.sessions.storage.client


def test_memory_session_transport_ignores_crudauth_redis(get_session, UserModel, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        auth = CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            redis_client=fakeredis.aioredis.FakeRedis(),
            transports=[SessionTransport(backend="memory")],
            email=_email(),
        )

    assert isinstance(auth.sessions.storage, MemorySessionStorage)
    assert isinstance(_token_store(auth), RedisSessionStorage)
    assert "sessions/CSRF" in caplog.text
    assert "rate limiter" not in caplog.text
    assert "one-time-token" not in caplog.text


def test_default_config_warns_about_each_memory_store(get_session, UserModel, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(session=get_session, user_model=UserModel, SECRET_KEY=SECRET, email=_email())

    for part in ("rate limiter", "sessions/CSRF", "one-time-token/OAuth-state stores"):
        assert part in caplog.text


def test_session_transport_redis_still_backs_the_token_stores(get_session, UserModel) -> None:
    client = fakeredis.aioredis.FakeRedis()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(redis_client=client)],
        email=_email(),
        warn_on_memory_backend=False,
    )

    assert auth.sessions.storage.client is client
    assert _token_store(auth).client is client


def test_contradictory_redis_config_raises(get_session, UserModel) -> None:
    client = fakeredis.aioredis.FakeRedis()
    with pytest.raises(ValueError, match="mutually exclusive"):
        SessionTransport(redis_client=client, redis_url="redis://localhost")
    with pytest.raises(ValueError, match="backend='memory'"):
        SessionTransport(backend="memory", redis_url="redis://localhost")
    with pytest.raises(ValueError, match="mutually exclusive"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            redis_client=client,
            redis_url="redis://localhost",
        )


def test_redis_backends_default_to_localhost_without_a_url_or_client() -> None:
    assert _connection(RedisSessionStorage()) == ("localhost", 6379, 0)
    assert _connection(redis_rate_limiter()) == ("localhost", 6379, 0)


async def test_shutdown_closes_only_the_clients_crudauth_built(
    get_session, UserModel, monkeypatch
) -> None:
    sessions = fakeredis.aioredis.FakeRedis()
    limiter = fakeredis.aioredis.FakeRedis()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(redis_client=sessions)],
        rate_limiter=redis_rate_limiter(client=limiter),
        redis_url="redis://auth-redis.internal:6379/0",
        email=_email(),
        warn_on_memory_backend=False,
    )
    closed: list[str] = []
    monkeypatch.setattr(sessions, "aclose", _recording(closed, "sessions"))
    monkeypatch.setattr(limiter, "aclose", _recording(closed, "limiter"))
    monkeypatch.setattr(_token_store(auth).client, "aclose", _recording(closed, "built"))

    await auth.shutdown()

    assert closed == ["built"]


async def test_session_transport_url_shares_and_closes_one_client(
    get_session, UserModel, monkeypatch
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(redis_url="redis://sessions.internal:6379/3")],
        warn_on_memory_backend=False,
    )
    client = auth.sessions.storage.client
    closed: list[str] = []
    monkeypatch.setattr(client, "aclose", _recording(closed, "sessions"))

    await auth.shutdown()

    assert auth.sessions.csrf_storage.client is client
    assert _connection(auth.sessions.storage) == ("sessions.internal", 6379, 3)
    assert closed == ["sessions"]


async def test_redis_transactions_stay_within_one_hash_slot(
    get_session, UserModel, monkeypatch
) -> None:
    client = fakeredis.aioredis.FakeRedis()
    open_pipeline = client.pipeline
    slots_per_transaction: list[set[int]] = []

    def checked_pipeline(*args: Any, **kwargs: Any) -> Any:
        pipe = open_pipeline(*args, **kwargs)
        execute = pipe.execute

        async def execute_checked(*execute_args: Any, **execute_kwargs: Any) -> Any:
            keys = [command[1] for command, _ in pipe.command_stack]
            slots_per_transaction.append(
                {key_slot(key if isinstance(key, bytes) else str(key).encode()) for key in keys}
            )
            return await execute(*execute_args, **execute_kwargs)

        monkeypatch.setattr(pipe, "execute", execute_checked)
        return pipe

    monkeypatch.setattr(client, "pipeline", checked_pipeline)
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False), management_routes=True)],
        redis_client=client,
    )
    app = FastAPI()
    app.include_router(auth.router)
    body = {"username": "alice", "password": "pw123456"}

    await auth.initialize()
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as first,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as second,
    ):
        await first.post("/register", json={**body, "email": "a@x.com"})
        csrf = (await first.post("/login", data=body)).json()["csrf_token"]
        await second.post("/login", data=body)
        listed = await first.get("/sessions")
        logout_all = await first.post("/logout-all", headers={"X-CSRF-Token": csrf})
        logout = await first.post("/logout", headers={"X-CSRF-Token": csrf})
    await auth.shutdown()

    assert (listed.status_code, logout_all.status_code, logout.status_code) == (200, 200, 200)
    assert len(listed.json()) == 2
    assert slots_per_transaction
    assert all(len(slots) == 1 for slots in slots_per_transaction)

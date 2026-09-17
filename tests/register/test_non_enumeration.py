"""/register answers a taken and a free signup the same way, and throttles only valid attempts."""

from __future__ import annotations

from typing import Any

import bcrypt
import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth import (
    CookieConfig,
    CRUDAuth,
    DeliveryChannel,
    DeliveryIntent,
    EmailConfig,
    EmailSender,
    IdentityConfig,
    PasswordPolicy,
    SessionTransport,
    make_auth_identity,
)
from crudauth.ratelimit import RateLimit

SECRET = "test-secret-key-0123456789-0123456789"

_UsernameEmailRecovery: Any = make_auth_identity(
    identifiers=["username"], recovery="email", oauth=False
)
_UsernamePhoneRecovery: Any = make_auth_identity(
    identifiers=["username"], recovery="phone", oauth=False
)


class _Base(DeclarativeBase):
    pass


class EmailRecoveryUser(_Base, _UsernameEmailRecovery):
    __tablename__ = "enum_email_recovery_users"


class PhoneRecoveryUser(_Base, _UsernamePhoneRecovery):
    __tablename__ = "enum_phone_recovery_users"
    phone: Mapped[str | None] = mapped_column(String(32), unique=True, default=None)


class PhoneRegister(BaseModel):
    username: str
    phone: str
    password: str


class NoticeSender(EmailSender):
    def __init__(self) -> None:
        self.kinds: list[tuple[str, str]] = []

    async def send(self, *, to, subject, body, kind, context):
        self.kinds.append((kind, to))


class RecordingChannel(DeliveryChannel):
    def __init__(self) -> None:
        self.kinds: list[tuple[str, str]] = []

    async def deliver(self, intent: DeliveryIntent, db) -> None:
        self.kinds.append((intent.kind, intent.recipient))


@pytest.fixture
async def model_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(_Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def get_session():
        async with maker() as session:
            yield session

    yield get_session
    await engine.dispose()


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _app(auth: CRUDAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(auth.router)
    return app


async def test_a_taken_and_a_free_email_hash_the_password_the_same_number_of_times(
    get_session, UserModel, monkeypatch
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=NoticeSender(), frontend_url="https://app.example.com"),
    )
    app = _app(auth)
    hashes: list[bytes] = []
    real_hashpw = bcrypt.hashpw

    def counting_hashpw(password: bytes, salt: bytes) -> bytes:
        hashes.append(password)
        return real_hashpw(password, salt)

    monkeypatch.setattr(bcrypt, "hashpw", counting_hashpw)
    await auth.initialize()
    async with _client(app) as client:
        await client.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        free = len(hashes)
        taken = await client.post(
            "/register", json={"email": "a@x.com", "username": "bob", "password": "pw123456"}
        )
    await auth.shutdown()

    assert taken.status_code == 202
    assert (free, len(hashes) - free) == (1, 1)


async def test_a_taken_recovery_email_outside_the_login_fields_is_not_revealed(
    model_session,
) -> None:
    sender = NoticeSender()
    auth = CRUDAuth(
        session=model_session,
        user_model=EmailRecoveryUser,
        SECRET_KEY=SECRET,
        identity=IdentityConfig(login=["username"], recovery="email"),
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
    )
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as client:
        first = await client.post(
            "/register", json={"username": "alice", "email": "a@x.com", "password": "pw123456"}
        )
        taken = await client.post(
            "/register", json={"username": "bob", "email": "a@x.com", "password": "pw123456"}
        )
    await auth.shutdown()

    assert (first.status_code, taken.status_code) == (202, 202)
    assert first.json() == taken.json()
    assert ("existing_account", "a@x.com") in sender.kinds


async def test_a_taken_phone_is_not_revealed(model_session) -> None:
    channel = RecordingChannel()
    auth = CRUDAuth(
        session=model_session,
        user_model=PhoneRecoveryUser,
        SECRET_KEY=SECRET,
        identity=IdentityConfig(login=["username"], recovery="phone"),
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        channels=[channel],
        register_schema=PhoneRegister,
        register_extra_fields={"phone"},
    )
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as client:
        first = await client.post(
            "/register", json={"username": "alice", "phone": "+15550001", "password": "pw123456"}
        )
        taken = await client.post(
            "/register", json={"username": "bob", "phone": "+15550001", "password": "pw123456"}
        )
        username_taken = await client.post(
            "/register", json={"username": "alice", "phone": "+15550002", "password": "pw123456"}
        )
    await auth.shutdown()

    assert (first.status_code, taken.status_code) == (202, 202)
    assert first.json() == taken.json()
    assert ("existing_account", "+15550001") in channel.kinds
    assert username_taken.status_code == 422


async def test_the_register_limit_counts_only_signups_that_pass_validation(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        password_policy=PasswordPolicy(min_length=12),
        rate_limits={"register": RateLimit(2, 3600)},
    )
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as client:
        rejected = [
            (
                await client.post(
                    "/register",
                    json={"email": f"weak{i}@x.com", "username": f"weak{i}", "password": "short"},
                )
            ).status_code
            for i in range(3)
        ]
        accepted = [
            (
                await client.post(
                    "/register",
                    json={
                        "email": f"ok{i}@x.com",
                        "username": f"ok{i}",
                        "password": "long-enough-password",
                    },
                )
            ).status_code
            for i in range(3)
        ]
    await auth.shutdown()

    assert rejected == [422, 422, 422]
    assert accepted == [200, 200, 429]

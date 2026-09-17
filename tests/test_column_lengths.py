"""Values longer than their ``String(n)`` column are rejected before anything is written."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import String, TypeDecorator, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth import CookieConfig, CRUDAuth, EmailConfig, EmailSender, SessionTransport
from crudauth.exceptions import OAuthAccountException
from crudauth.models import AuthUserMixin
from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository

SECRET = "test-secret-key-0123456789-0123456789"
LONG_EMAIL = "abcdefghijklm@xyz.com"


class Nickname(TypeDecorator):
    impl = String(5)
    cache_ok = True


class SizedBase(DeclarativeBase):
    pass


class SizedUser(SizedBase, AuthUserMixin):
    __tablename__ = "sized_users"

    username: Mapped[str] = mapped_column(String(12), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(5), default=None)
    nickname: Mapped[str | None] = mapped_column(Nickname, default=None)


class Register(BaseModel):
    email: str
    username: str
    password: str
    full_name: str | None = None
    nickname: str | None = None


class RecordingSender(EmailSender):
    def __init__(self) -> None:
        self.kinds: list[str] = []

    async def send(self, *, to, subject, body, kind, context):
        self.kinds.append(kind)


def too_long(field: str, limit: int) -> dict[str, Any]:
    return {
        "type": "string_too_long",
        "loc": ["body", field],
        "msg": f"String should have at most {limit} characters",
        "ctx": {"max_length": limit},
    }


@pytest.fixture
async def sized_sessionmaker():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(SizedBase.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()


def _auth(sized_sessionmaker, **options) -> CRUDAuth:
    async def get_session():
        async with sized_sessionmaker() as session:
            yield session

    return CRUDAuth(
        session=get_session,
        user_model=SizedUser,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        **options,
    )


def _client(auth: CRUDAuth) -> httpx.AsyncClient:
    app = FastAPI()
    app.include_router(auth.router)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_register_reports_every_value_longer_than_its_column(sized_sessionmaker) -> None:
    auth = _auth(
        sized_sessionmaker,
        register_schema=Register,
        register_extra_fields={"full_name", "nickname"},
    )
    too_long_body = {
        "email": LONG_EMAIL,
        "username": "a" * 13,
        "password": "pw123456",
        "full_name": "Alice Smith",
        "nickname": "sixsix",
    }
    at_the_limit = {
        "email": "abcdefghijkl@xyz.com",
        "username": "a" * 12,
        "password": "pw123456",
        "full_name": "Alice",
        "nickname": "fives",
    }

    await auth.initialize()
    async with _client(auth) as c:
        rejected = await c.post("/register", json=too_long_body)
        accepted = await c.post("/register", json=at_the_limit)
    await auth.shutdown()

    assert rejected.status_code == 422
    assert sorted(rejected.json()["detail"], key=lambda error: error["loc"]) == [
        too_long("email", 20),
        too_long("full_name", 5),
        too_long("nickname", 5),
        too_long("username", 12),
    ]
    assert accepted.status_code == 200, accepted.text
    async with sized_sessionmaker() as db:
        assert await db.scalar(select(func.count()).select_from(SizedUser)) == 1


async def test_register_measures_the_email_as_it_will_be_stored(sized_sessionmaker) -> None:
    auth = _auth(sized_sessionmaker, register_schema=Register)
    body = {"email": "  ABCDEFGHIJKL@XYZ.COM  ", "username": "alice", "password": "pw123456"}

    await auth.initialize()
    async with _client(auth) as c:
        response = await c.post("/register", json=body)
    await auth.shutdown()

    assert response.status_code == 200, response.text
    assert response.json()["email"] == "abcdefghijkl@xyz.com"


async def test_email_change_request_rejects_an_address_longer_than_the_column(
    sized_sessionmaker,
) -> None:
    sender = RecordingSender()
    auth = _auth(
        sized_sessionmaker,
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
    )

    await auth.initialize()
    async with _client(auth) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        login = await c.post("/login", data={"username": "alice", "password": "pw123456"})
        response = await c.post(
            "/email/change-request",
            json={"new_email": LONG_EMAIL, "password": "pw123456"},
            headers={"X-CSRF-Token": login.json()["csrf_token"]},
        )
    await auth.shutdown()

    assert response.status_code == 422
    assert response.json() == {"detail": [too_long("new_email", 20)]}
    assert "change_email" not in sender.kinds


async def test_oauth_signup_rejects_an_email_longer_than_the_column(sized_sessionmaker) -> None:
    service = OAuthAccountService(UserRepository(SizedUser))
    info = OAuthUserInfo(
        provider="google", provider_user_id="g-1", email=LONG_EMAIL, email_verified=True
    )
    async with sized_sessionmaker() as db:
        with pytest.raises(OAuthAccountException) as exc:
            await service.get_or_create_user(info, db)
        assert await db.scalar(select(func.count()).select_from(SizedUser)) == 0
    assert exc.value.code == "email_too_long"

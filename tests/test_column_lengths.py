"""Values longer than their ``String(n)`` column are rejected before anything is written."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel, EmailStr
from sqlalchemy import String, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth import CookieConfig, CRUDAuth, EmailConfig, EmailSender, SessionTransport
from crudauth.exceptions import BadRequestException
from crudauth.models import AuthUserMixin
from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository

SECRET = "test-secret-key-0123456789-0123456789"
LONG_EMAIL = "abcdefghijklm@xyz.com"


class SizedBase(DeclarativeBase):
    pass


class SizedUser(SizedBase, AuthUserMixin):
    __tablename__ = "sized_users"

    username: Mapped[str] = mapped_column(String(12), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(5), default=None)


class Register(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: str | None = None


class RecordingSender(EmailSender):
    def __init__(self) -> None:
        self.kinds: list[str] = []

    async def send(self, *, to, subject, body, kind, context):
        self.kinds.append(kind)


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


async def test_register_rejects_values_longer_than_their_column(sized_sessionmaker) -> None:
    auth = _auth(sized_sessionmaker, register_schema=Register, register_extra_fields={"full_name"})
    body = {"email": "new@x.com", "username": "new", "password": "pw123456"}
    fitting = {**body, "email": "abcdefghijkl@xyz.com", "username": "a" * 12, "full_name": "Alice"}

    await auth.initialize()
    async with _client(auth) as c:
        long_username = await c.post("/register", json={**body, "username": "a" * 13})
        long_email = await c.post("/register", json={**body, "email": LONG_EMAIL})
        long_name = await c.post("/register", json={**body, "full_name": "Alice Smith"})
        fits = await c.post("/register", json=fitting)
    await auth.shutdown()

    assert long_username.status_code == 422
    assert long_username.json() == {"detail": "Username must be at most 12 characters"}
    assert long_email.status_code == 422
    assert long_email.json() == {"detail": "Email must be at most 20 characters"}
    assert long_name.status_code == 422
    assert long_name.json() == {"detail": "Full name must be at most 5 characters"}
    assert fits.status_code == 200, fits.text
    async with sized_sessionmaker() as db:
        assert await db.scalar(select(func.count()).select_from(SizedUser)) == 1


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
    assert response.json() == {"detail": "Email must be at most 20 characters"}
    assert "change_email" not in sender.kinds


async def test_oauth_signup_rejects_an_email_longer_than_the_column(sized_sessionmaker) -> None:
    service = OAuthAccountService(UserRepository(SizedUser))
    info = OAuthUserInfo(
        provider="google", provider_user_id="g-1", email=LONG_EMAIL, email_verified=True
    )
    async with sized_sessionmaker() as db:
        with pytest.raises(BadRequestException):
            await service.get_or_create_user(info, db)
        assert await db.scalar(select(func.count()).select_from(SizedUser)) == 0

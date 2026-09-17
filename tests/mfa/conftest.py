"""An app whose user model carries the MFA columns, and helpers to drive the flows."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth import CookieConfig, CRUDAuth, MfaConfig, SessionTransport, make_auth_identity
from crudauth.mfa.totp import totp_code

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "pw123456"
MFA_KEY = Fernet.generate_key().decode()

MfaIdentity: Any = make_auth_identity(mfa=True)


class MfaBase(DeclarativeBase):
    pass


class MfaUser(MfaBase, MfaIdentity):
    __tablename__ = "mfa_users"
    stub_id: Mapped[str | None] = mapped_column(default=None)


@pytest_asyncio.fixture
async def mfa_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(MfaBase.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()


@pytest.fixture
def mfa_session(mfa_sessionmaker) -> Callable[[], AsyncIterator[AsyncSession]]:
    async def get_session() -> AsyncIterator[AsyncSession]:
        async with mfa_sessionmaker() as session:
            yield session

    return get_session


@pytest.fixture
def build(mfa_session) -> Callable[..., tuple[CRUDAuth, FastAPI]]:
    def _build(
        mfa: MfaConfig | None = None, transports: list[Any] | None = None, **options: Any
    ) -> tuple[CRUDAuth, FastAPI]:
        auth = CRUDAuth(
            session=mfa_session,
            user_model=MfaUser,
            SECRET_KEY=SECRET,
            transports=transports or [SessionTransport(cookies=CookieConfig(secure=False))],
            mfa=mfa or MfaConfig(issuer="Acme", encryption_key=MFA_KEY),
            warn_on_memory_backend=False,
            **options,
        )
        app = FastAPI()
        app.include_router(auth.router)
        return auth, app

    return _build


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def code_for(secret: str, offset_steps: int = 0) -> str:
    return totp_code(secret, int(time.time() // 30) + offset_steps)


async def register_and_login(browser: httpx.AsyncClient, username: str = "alice") -> httpx.Response:
    await browser.post(
        "/register",
        json={"email": f"{username}@x.com", "username": username, "password": PASSWORD},
    )
    return await browser.post("/login", data={"username": username, "password": PASSWORD})


async def enroll(browser: httpx.AsyncClient, csrf: str) -> tuple[str, list[str]]:
    headers = {"X-CSRF-Token": csrf}
    setup = await browser.post("/mfa/totp/setup", json={"password": PASSWORD}, headers=headers)
    secret = setup.json()["secret"]
    confirm = await browser.post(
        "/mfa/totp/confirm", json={"code": code_for(secret, -1)}, headers=headers
    )
    return secret, confirm.json()["recovery_codes"]

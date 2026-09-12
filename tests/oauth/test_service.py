"""Unit tests for OAuthAccountService account linking (create / link existing)."""

from __future__ import annotations

import pytest
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash


class ShortBase(DeclarativeBase):
    pass


class ShortUser(ShortBase):
    __tablename__ = "short_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    username: Mapped[str] = mapped_column(String(12), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str | None] = mapped_column(String(7), default=None)


@pytest.fixture
async def short_sessionmaker():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(ShortBase.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()


async def test_oauth_creates_then_links(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)

    info = OAuthUserInfo(
        provider="google",
        provider_user_id="g-1",
        email="Person@Example.com",
        email_verified=True,
        name="A Person",
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
        assert created is True
        assert repo.get(user, "email") == "person@example.com"
        assert repo.get(user, "google_id") == "g-1"

    # second time → same account, not created
    async with sessionmaker() as db:
        user2, created2 = await service.get_or_create_user(info, db)
        assert created2 is False
        assert repo.user_id(user2) == repo.user_id(user)


async def test_oauth_links_existing_email(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)
    # pre-existing password user
    async with sessionmaker() as db:
        existing = await repo.create(
            db,
            {
                "email": "dup@x.com",
                "username": "dup",
                "hashed_password": get_password_hash("pw"),
            },
        )
        existing_id = repo.user_id(existing)

    info = OAuthUserInfo(
        provider="github", provider_user_id="gh-9", email="dup@x.com", email_verified=True
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
        assert created is False
        assert repo.user_id(user) == existing_id
        assert repo.get(user, "github_id") == "gh-9"


async def test_oauth_usernames_fit_column_and_suffixes(short_sessionmaker) -> None:
    repo = UserRepository(ShortUser)
    service = OAuthAccountService(repo, lambda ctx: {"name": ctx.suggested_name})
    info = OAuthUserInfo(
        provider="google",
        provider_user_id="g-1",
        email="first@example.com",
        name="__Very Long Display Name__",
    )
    async with short_sessionmaker() as db:
        user, _ = await service.get_or_create_user(info, db)
        assert user.username == "very_long_di"
        assert user.name == "__Very "

        second = info.model_copy(update={"provider_user_id": "g-2", "email": "second@example.com"})
        user2, _ = await service.get_or_create_user(second, db)
        assert user2.username == "very_long_1"
        assert len(user2.username) <= 12
        assert "__" not in user2.username
        assert not user2.username.startswith("_")
        assert not user2.username.endswith("_")


async def test_oauth_random_username_fits_short_column(short_sessionmaker) -> None:
    service = OAuthAccountService(UserRepository(ShortUser))
    username = service._random_username("verylongname")
    assert len(username) <= 12
    assert "__" not in username
    assert not username.startswith("_")
    assert not username.endswith("_")

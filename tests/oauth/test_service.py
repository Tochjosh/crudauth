"""Unit tests for OAuthAccountService account linking (create / link existing)."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash

USERNAME_PATTERN = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)*")


class ShortBase(DeclarativeBase):
    pass


class ShortUser(ShortBase):
    __tablename__ = "short_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    username: Mapped[str] = mapped_column(String(12), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(100))


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
    service = OAuthAccountService(UserRepository(ShortUser))
    info = OAuthUserInfo(
        provider="google",
        provider_user_id="g-1",
        email="first@example.com",
        name="__Very Long Display Name__",
    )
    second = info.model_copy(update={"provider_user_id": "g-2", "email": "second@example.com"})
    async with short_sessionmaker() as db:
        first_user, _ = await service.get_or_create_user(info, db)
        second_user, _ = await service.get_or_create_user(second, db)
    assert first_user.username == "very_long_di"
    assert second_user.username == "very_long_1"


async def test_oauth_suffix_never_doubles_the_separator(short_sessionmaker) -> None:
    repo = UserRepository(ShortUser)
    service = OAuthAccountService(repo)
    taken = "aaaaaaaaa_bb"
    info = OAuthUserInfo(
        provider="google", provider_user_id="g-1", email="new@example.com", username=taken
    )
    async with short_sessionmaker() as db:
        await repo.create(
            db, {"email": "taken@example.com", "username": taken, "hashed_password": "h"}
        )
        user, _ = await service.get_or_create_user(info, db)
    assert user.username == "aaaaaaaaa_1"


async def test_oauth_random_suffix_fits_short_column(short_sessionmaker, monkeypatch) -> None:
    repo = UserRepository(ShortUser)

    async def always_taken(db, username):
        return True

    monkeypatch.setattr(repo, "username_exists", always_taken)
    service = OAuthAccountService(repo)
    info = OAuthUserInfo(
        provider="google",
        provider_user_id="g-1",
        email="first@example.com",
        name="Very Long Display Name",
    )
    async with short_sessionmaker() as db:
        user, _ = await service.get_or_create_user(info, db)
    assert len(user.username) == 12
    assert user.username.startswith("ver_")
    assert USERNAME_PATTERN.fullmatch(user.username)

"""OAuth provider normalization + account-service edge cases."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from crudauth import OAuthAccountException
from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.oauth.providers.github import GitHubOAuthProvider, _select_github_email
from crudauth.oauth.providers.google import GoogleOAuthProvider
from crudauth.repository import UserRepository


async def test_google_missing_sub_raises() -> None:
    prov = GoogleOAuthProvider("id", "secret", "http://cb")
    with pytest.raises(ValueError, match="sub"):
        await prov.process_user_info({"email": "a@x.com"})


async def test_github_missing_id_raises() -> None:
    prov = GitHubOAuthProvider("id", "secret", "http://cb")
    with pytest.raises(ValueError, match="user id"):
        await prov.process_user_info({"login": "octocat"})


@pytest.mark.parametrize("flag", ["true", "false", 1, None])
async def test_google_only_a_json_true_verifies_the_email(flag) -> None:
    prov = GoogleOAuthProvider("id", "secret", "http://cb")
    info = await prov.process_user_info({"sub": "g-1", "email": "a@x.com", "email_verified": flag})
    assert info.email_verified is False


@pytest.mark.parametrize("flag", ["true", "false", 1])
def test_github_only_a_json_true_verifies_the_email(flag) -> None:
    assert _select_github_email([{"email": "a@x.com", "primary": True, "verified": flag}]) == (
        "a@x.com",
        False,
    )


async def test_google_uses_real_sub() -> None:
    prov = GoogleOAuthProvider("id", "secret", "http://cb")
    info = await prov.process_user_info(
        {"sub": "g-123", "email": "a@x.com", "email_verified": True}
    )
    assert info.provider_user_id == "g-123"
    assert info.email_verified is True


# --- GitHub email selection never lets an unverified primary win ----------
def test_github_email_prefers_primary_verified() -> None:
    email, verified = _select_github_email(
        [
            {"email": "secondary@x.com", "primary": False, "verified": True},
            {"email": "primary@x.com", "primary": True, "verified": True},
        ]
    )
    assert (email, verified) == ("primary@x.com", True)


def test_github_email_unverified_primary_does_not_win() -> None:
    # primary is unverified, a secondary is verified → take the verified one
    email, verified = _select_github_email(
        [
            {"email": "primary@x.com", "primary": True, "verified": False},
            {"email": "verified@x.com", "primary": False, "verified": True},
        ]
    )
    assert (email, verified) == ("verified@x.com", True)


def test_github_email_all_unverified_keeps_flag_false() -> None:
    email, verified = _select_github_email(
        [{"email": "primary@x.com", "primary": True, "verified": False}]
    )
    assert (email, verified) == ("primary@x.com", False)


def test_github_email_empty() -> None:
    assert _select_github_email([]) == (None, False)


async def test_oauth_refuses_to_create_an_account_from_an_unverified_email(
    sessionmaker, UserModel
) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)
    info = OAuthUserInfo(
        provider="google", provider_user_id="g-new", email="fresh@x.com", email_verified=False
    )
    async with sessionmaker() as db:
        with pytest.raises(OAuthAccountException) as exc:
            await service.get_or_create_user(info, db)
        assert await repo.get_by_email(db, "fresh@x.com") is None
    assert (exc.value.status_code, exc.value.code) == (400, "email_unverified")


# --- username generation is bounded and survives an insert race ----------
async def test_unique_username_falls_back_to_random(sessionmaker, UserModel) -> None:
    class AllTakenRepo(UserRepository):
        async def username_exists(self, db, username):  # type: ignore[override]
            return True  # every numbered candidate is "taken"

    repo = AllTakenRepo(UserModel)
    service = OAuthAccountService(repo)
    async with sessionmaker() as db:
        result = await service._unique_username(db, "alice")
    # terminated (no infinite loop) and used a random suffix, not a numbered one
    assert result.startswith("alice_")
    assert result != "alice_1"


async def test_create_user_retries_on_integrity_error(sessionmaker, UserModel) -> None:
    class FlakyRepo(UserRepository):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.create_calls = 0

        async def create(self, db, data):
            self.create_calls += 1
            if self.create_calls == 1:
                raise IntegrityError("INSERT", {}, Exception("duplicate username"))
            return await UserRepository.create(self, db, data)

    repo = FlakyRepo(UserModel)
    service = OAuthAccountService(repo)
    info = OAuthUserInfo(
        provider="google", provider_user_id="g-race", email="race@x.com", email_verified=True
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
    assert created is True
    assert repo.create_calls == 2  # first raced, retried with a random username
    assert repo.user_id(user) is not None


def test_google_authorize_url_has_no_forced_offline_consent() -> None:
    # crudauth never uses a refresh token, so Google's authorize URL must not
    # force access_type=offline / prompt=consent (would re-prompt every login).
    prov = GoogleOAuthProvider("id", "sec", "https://app/cb")
    url = prov.get_authorization_url()["url"]
    assert "access_type" not in url
    assert "prompt=consent" not in url

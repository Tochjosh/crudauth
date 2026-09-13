from __future__ import annotations

from typing import Any

import fakeredis.aioredis
import pytest

from crudauth import CRUDAuth, SessionTransport
from crudauth.ratelimit import RedisBackend
from crudauth.storage.backends.redis import RedisSessionStorage


def redis_client():
    return fakeredis.aioredis.FakeRedis()


def test_redis_client_and_url_are_exclusive(get_session, UserModel) -> None:
    client = redis_client()
    with pytest.raises(ValueError, match="mutually exclusive"):
        SessionTransport(redis_client=client, redis_url="redis://localhost")
    with pytest.raises(ValueError, match="mutually exclusive"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="secret",
            redis_client=client,
            redis_url="redis://localhost",
        )


async def test_injected_redis_is_shared_and_not_closed(get_session, UserModel) -> None:
    client = redis_client()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="secret",
        transports=[SessionTransport(redis_client=client)],
        redis_client=client,
        warn_on_memory_backend=False,
    )

    assert isinstance(auth.runtime.rate_limiter, RedisBackend)
    assert auth.runtime.rate_limiter.client is client
    assert isinstance(auth.sessions.storage, RedisSessionStorage)
    assert isinstance(auth.sessions.csrf_storage, RedisSessionStorage)
    assert auth.sessions.storage.client is client
    assert auth.sessions.csrf_storage.client is client

    await auth.shutdown()
    assert await client.ping() is True
    await client.aclose()


def test_injected_storage_client_is_caller_owned() -> None:
    client = redis_client()
    storage: RedisSessionStorage[Any] = RedisSessionStorage(client=client)
    assert storage._owns_client is False


async def test_injected_redis_reaches_email_and_oauth_stores(get_session, UserModel) -> None:
    from crudauth import OAuthCredentials
    from crudauth.email import EmailConfig, EmailSender

    class NoopSender(EmailSender):
        async def send(self, **kwargs):
            pass

    client = redis_client()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="secret",
        transports=[SessionTransport(redis_client=client)],
        redis_client=client,
        email=EmailConfig(sender=NoopSender()),
        oauth={"google": OAuthCredentials(client_id="id", client_secret="secret")},
        redirect_base_url="http://test",
        warn_on_memory_backend=False,
    )

    assert isinstance(auth._email_token_store, RedisSessionStorage)
    assert isinstance(auth._oauth_state_storage, RedisSessionStorage)
    assert auth._email_token_store.client is client
    assert auth._oauth_state_storage.client is client

    await auth.shutdown()
    assert await client.ping() is True
    await client.aclose()

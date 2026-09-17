"""Optional custom registration schema: opted-in extra fields persist (not required)."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from crudauth import CookieConfig, CRUDAuth, PasswordContext, PasswordPolicy, SessionTransport
from crudauth.repository import UserRepository


class RegisterWithName(BaseModel):
    email: str
    username: str
    password: str
    full_name: str


@pytest.fixture
async def ctx(get_session, UserModel, sessionmaker):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        register_schema=RegisterWithName,
        register_extra_fields={"full_name"},
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, sessionmaker, UserModel
    await auth.shutdown()


async def test_custom_field_persisted(ctx) -> None:
    client, sessionmaker, UserModel = ctx
    r = await client.post(
        "/register",
        json={
            "email": "a@x.com",
            "username": "alice",
            "password": "pw123456",
            "full_name": "Alice Doe",
        },
    )
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "a@x.com")
    assert user is not None
    assert user.full_name == "Alice Doe"


async def test_custom_schema_requires_its_fields(ctx) -> None:
    client, *_ = ctx
    # full_name is required by the custom schema → 422 when missing
    r = await client.post(
        "/register",
        json={"email": "b@x.com", "username": "bob", "password": "pw123456"},
    )
    assert r.status_code == 422


async def test_default_schema_still_works(get_session, UserModel) -> None:
    # No register_schema → the built-in 3-field body is used.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post(
            "/register", json={"email": "c@x.com", "username": "carol", "password": "pw123456"}
        )
        assert r.status_code == 200
    await auth.shutdown()


def _policy_app(get_session, UserModel, policy: PasswordPolicy, **options):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        password_policy=policy,
        **options,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return app, auth


async def _post_register(app, auth, body: dict) -> httpx.Response:
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        response = await c.post("/register", json=body)
    await auth.shutdown()
    return response


async def test_register_rejects_a_password_that_fails_the_policy(get_session, UserModel) -> None:
    app, auth = _policy_app(get_session, UserModel, PasswordPolicy(min_length=12))
    body = {"email": "policy@x.com", "username": "policy", "password": "tenchars10"}

    response = await _post_register(app, auth, body)

    assert response.status_code == 422
    assert response.json() == {
        "detail": [
            {
                "type": "string_too_short",
                "loc": ["body", "password"],
                "msg": "String should have at least 12 characters",
                "ctx": {"min_length": 12},
            }
        ]
    }


async def test_policy_can_allow_passwords_shorter_than_the_default(get_session, UserModel) -> None:
    app, auth = _policy_app(get_session, UserModel, PasswordPolicy(min_length=6))
    body = {"email": "six@x.com", "username": "six", "password": "seven77"}

    response = await _post_register(app, auth, body)

    assert response.status_code == 200, response.text


def test_openapi_documents_the_policy(get_session, UserModel) -> None:
    app, _ = _policy_app(get_session, UserModel, PasswordPolicy(min_length=12, require_digit=True))

    password = app.openapi()["components"]["schemas"]["RegisterIn"]["properties"]["password"]

    assert password["minLength"] == 12
    assert password["description"] == "At least 12 characters, including a digit."


async def test_custom_schema_gets_the_policy_with_the_submitted_identity(
    get_session, UserModel
) -> None:
    contexts: list[PasswordContext] = []

    def not_personal(password: str, context: PasswordContext) -> None:
        contexts.append(context)
        if context.username and context.username in password:
            raise ValueError("Password should not contain your username")

    app, auth = _policy_app(
        get_session,
        UserModel,
        PasswordPolicy(validators=[not_personal]),
        register_schema=RegisterWithName,
        register_extra_fields={"full_name"},
    )
    body = {
        "email": "dana@x.com",
        "username": "dana",
        "password": "dana-password",
        "full_name": "Dana",
    }

    response = await _post_register(app, auth, body)

    assert response.status_code == 422
    assert response.json() == {
        "detail": [
            {
                "type": "password_policy",
                "loc": ["body", "password"],
                "msg": "Password should not contain your username",
            }
        ]
    }
    assert contexts == [PasswordContext(source="register", username="dana", email="dana@x.com")]

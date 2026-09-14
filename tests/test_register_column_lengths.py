"""``/register`` rejects values longer than their column before writing anything."""

from __future__ import annotations

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select

from crudauth import CookieConfig, CRUDAuth, SessionTransport

SECRET = "test-secret-key-0123456789-0123456789"


class Register(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: str | None = None


async def test_register_rejects_values_longer_than_their_column(
    get_session, UserModel, sessionmaker, monkeypatch
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        register_schema=Register,
        register_extra_fields={"full_name"},
    )
    monkeypatch.setattr(auth.repo, "string_length", {"username": 12, "full_name": 5}.get)
    app = FastAPI()
    app.include_router(auth.router)
    body = {"email": "new@x.com", "username": "new", "password": "pw123456"}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        long_username = await c.post("/register", json={**body, "username": "a" * 13})
        long_name = await c.post("/register", json={**body, "full_name": "Alice Smith"})
        fits = await c.post("/register", json={**body, "username": "a" * 12, "full_name": "Alice"})
    await auth.shutdown()

    assert long_username.status_code == 422
    assert long_username.json() == {"detail": "Username must be at most 12 characters"}
    assert long_name.status_code == 422
    assert long_name.json() == {"detail": "Full name must be at most 5 characters"}
    assert fits.status_code == 200, fits.text
    async with sessionmaker() as db:
        assert await db.scalar(select(func.count()).select_from(UserModel)) == 1

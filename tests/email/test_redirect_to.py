"""The destination an app asks to return to, carried inside the signed token."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from fastapi import FastAPI

from crudauth import (
    CookieConfig,
    CRUDAuth,
    EmailConfig,
    EmailSender,
    SessionTransport,
)
from crudauth.email.constants import REDIRECT_CLAIM
from crudauth.transports.bearer.tokens import create_signed_token, verify_signed_token_full

SECRET = "test-secret-key-0123456789-0123456789"


class CapturingSender(EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, *, to, subject, body, kind, context):
        self.sent.append({"to": to, "body": body, "kind": kind})

    def token_for(self, kind: str) -> str:
        for message in reversed(self.sent):
            if message["kind"] == kind:
                return message["body"].split("token=")[-1]
        raise AssertionError(f"no {kind} email captured")

    def link_for(self, kind: str) -> str:
        for message in reversed(self.sent):
            if message["kind"] == kind:
                return message["body"]
        raise AssertionError(f"no {kind} email captured")


@pytest.fixture
async def ctx(get_session, UserModel):
    sender = CapturingSender()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client, sender, auth
    await auth.shutdown()


async def _register(client) -> None:
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )


async def _verify_token(client, sender, **body) -> str:
    response = await client.post("/email/verify-request", json={"email": "a@x.com", **body})
    assert response.status_code == 200
    return sender.token_for("verify_email")


def _claims(token: str, purpose: str) -> dict:
    payload = verify_signed_token_full(token, SECRET, purpose)
    assert payload is not None
    return payload


# --- the round trip ----------------------------------------------------------
async def test_verification_returns_where_the_request_asked_to_go(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to="/j/abc123")

    response = await client.post("/email/verify-confirm", json={"token": token})

    assert response.status_code == 200
    assert response.json() == {"detail": "Verified successfully.", "redirect_to": "/j/abc123"}


async def test_the_emailed_link_is_unchanged(ctx) -> None:
    """The destination rides in the token, so the URL has nothing to tamper with."""
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to="/j/abc123")

    link = sender.link_for("verify_email")

    assert f"https://app.example.com/verify-email?token={token}" in link
    assert "abc123" not in link.replace(token, "")


async def test_the_destination_travels_in_the_signed_token(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to="/j/abc123")

    assert _claims(token, "verify_email")[REDIRECT_CLAIM] == "/j/abc123"


async def test_without_a_destination_nothing_changes(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender)

    assert REDIRECT_CLAIM not in _claims(token, "verify_email")
    response = await client.post("/email/verify-confirm", json={"token": token})
    assert response.json() == {"detail": "Verified successfully."}


# --- what a destination may be -----------------------------------------------
@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example.com/steal",
        "//evil.example.com",
        "/\\evil.example.com",
        "javascript:alert(1)",
        "/path\nwith-control",
        "",
    ],
)
async def test_a_destination_that_cannot_be_honored_is_dropped(ctx, target: str) -> None:
    """A rejected target mints no claim, and never stops someone verifying their email."""
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to=target)

    assert REDIRECT_CLAIM not in _claims(token, "verify_email")
    response = await client.post("/email/verify-confirm", json={"token": token})
    assert response.status_code == 200
    assert response.json() == {"detail": "Verified successfully."}


async def test_a_relative_path_keeps_its_query_and_fragment(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to="/invites/7?from=email#top")

    response = await client.post("/email/verify-confirm", json={"token": token})

    assert response.json()["redirect_to"] == "/invites/7?from=email#top"


async def test_a_forged_destination_does_not_survive_the_signature(ctx) -> None:
    """A destination rewritten in the token invalidates it; the flow is refused."""
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to="/j/abc123")
    head, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims[REDIRECT_CLAIM] = "/j/attacker"
    rewritten = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")

    response = await client.post(
        "/email/verify-confirm", json={"token": ".".join([head, rewritten, signature])}
    )

    assert response.status_code == 400


async def test_a_claim_signed_with_an_unsafe_target_is_still_refused(ctx) -> None:
    """Validation runs again at redemption, not only when the token is minted."""
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender)
    payload = _claims(token, "verify_email")
    smuggled = create_signed_token(
        SECRET,
        payload["sub"],
        "verify_email",
        expires_hours=1,
        extra_claims={"state": payload["state"], REDIRECT_CLAIM: "https://evil.example.com"},
    )

    response = await client.post("/email/verify-confirm", json={"token": smuggled})

    assert response.status_code == 200
    assert response.json() == {"detail": "Verified successfully."}


# --- the other two flows -----------------------------------------------------
async def test_password_reset_carries_the_destination(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    await client.post("/password/reset-request", json={"email": "a@x.com", "redirect_to": "/cart"})
    token = sender.token_for("reset_password")

    response = await client.post(
        "/password/reset-confirm", json={"token": token, "new_password": "newpw12345"}
    )

    assert response.json() == {"detail": "Password reset successfully.", "redirect_to": "/cart"}


async def test_email_change_carries_the_destination(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    csrf = login.json()["csrf_token"]

    await client.post(
        "/email/change-request",
        json={"new_email": "alice2@x.com", "password": "pw123456", "redirect_to": "/settings"},
        headers={"X-CSRF-Token": csrf},
    )
    token = sender.token_for("change_email")

    response = await client.post("/email/change-confirm", json={"token": token})

    assert response.json() == {"detail": "Email changed successfully.", "redirect_to": "/settings"}


# --- a used token still can't be replayed ------------------------------------
async def test_a_used_token_is_refused_even_with_a_destination(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to="/j/abc123")

    first = await client.post("/email/verify-confirm", json={"token": token})
    second = await client.post("/email/verify-confirm", json={"token": token})

    assert first.status_code == 200
    assert second.status_code == 400
    assert "redirect_to" not in second.json()


# --- the service hands both back ---------------------------------------------
async def test_the_service_returns_the_user_and_the_destination(ctx) -> None:
    client, sender, auth = ctx
    await _register(client)
    token = await _verify_token(client, sender, redirect_to="/j/abc123")
    service = auth.emails
    assert service is not None

    async for db in auth.session():
        result = await service.confirm_recovery_verification(db, token)
        break

    assert result.redirect_to == "/j/abc123"
    assert auth.repo.get(result.user, "email") == "a@x.com"

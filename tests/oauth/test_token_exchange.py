"""Token exchange client authentication: confidential and public clients."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlparse

import httpx
import pytest
from fastapi import FastAPI

from crudauth import CookieConfig, CRUDAuth, OAuthCredentials, SessionTransport
from crudauth.oauth import AbstractOAuthProvider, OAuthProviderFactory, OAuthUserInfo

SECRET = "test-secret-key-0123456789-0123456789"


class IdentityProvider(AbstractOAuthProvider):
    def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=scopes or ["openid", "email"],
            authorize_endpoint="https://idp.example/authorize",
            token_endpoint="https://idp.example/token",
            userinfo_endpoint="https://idp.example/userinfo",
            provider_name="stub",
        )

    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider="stub",
            provider_user_id=user_info["sub"],
            email=user_info["email"],
            email_verified=True,
        )


def _capture_provider_requests(monkeypatch) -> list[httpx.Request]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "tok", "token_type": "Bearer"})
        return httpx.Response(200, json={"sub": "idp-1", "email": "public@x.com"})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    return requests


def _form(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode(), keep_blank_values=True))


@pytest.mark.parametrize(
    ("client_secret", "expected"),
    [("s3cret", {"client_secret": "s3cret"}), ("", {})],
)
async def test_exchange_code_sends_the_secret_only_when_set(
    monkeypatch, client_secret: str, expected: dict[str, str]
) -> None:
    requests = _capture_provider_requests(monkeypatch)
    provider = IdentityProvider("cid", client_secret, "https://app/cb")

    token = await provider.exchange_code("code-1", code_verifier="ver-1")

    assert token["access_token"] == "tok"
    assert _form(requests[0]) == {
        "client_id": "cid",
        "code": "code-1",
        "redirect_uri": "https://app/cb",
        "grant_type": "authorization_code",
        "code_verifier": "ver-1",
        **expected,
    }


async def test_public_client_signs_in_without_a_secret(get_session, UserModel, monkeypatch) -> None:
    monkeypatch.setitem(OAuthProviderFactory._providers, "stub", IdentityProvider)
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"stub": OAuthCredentials(client_id="public-client")},
        redirect_base_url="http://test",
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        requests = _capture_provider_requests(monkeypatch)
        authorize = await client.get("/oauth/stub/authorize")
        state = parse_qs(urlparse(authorize.headers["location"]).query)["state"][0]
        callback = await client.get(f"/oauth/stub/callback?code=abc&state={state}")
        me = await client.get("/me")
    await auth.shutdown()

    assert callback.status_code == 307
    assert me.json()["email"] == "public@x.com"
    token_form = _form(requests[0])
    assert token_form["client_id"] == "public-client"
    assert "code_verifier" in token_form
    assert "client_secret" not in token_form


@pytest.mark.parametrize("provider", ["google", "github"])
def test_providers_that_require_a_secret_fail_at_startup_without_one(
    get_session, UserModel, provider: str
) -> None:
    with pytest.raises(ValueError, match="needs a client_secret"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            oauth={provider: OAuthCredentials(client_id="id")},
            redirect_base_url="http://test",
        )


def test_credentials_repr_hides_the_secret() -> None:
    credentials = OAuthCredentials(client_id="id", client_secret="do-not-print")

    assert "do-not-print" not in repr(credentials)
    assert credentials.client_secret == "do-not-print"

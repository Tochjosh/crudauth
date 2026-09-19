"""A callback whose state check fails: back to the app in redirect mode, a 400 in JSON mode."""

from __future__ import annotations

from typing import Literal
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from crudauth import CookieConfig, CRUDAuth, OAuthCredentials, SessionTransport
from crudauth.oauth import OAuthProviderFactory

from .test_flow import StubProvider

INVALID_STATE_LOCATION = "http://test?error=invalid_state"
JSON_DETAIL = {"detail": "Invalid or expired OAuth state"}


class OtherStubProvider(StubProvider):
    def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
        super().__init__(client_id, client_secret, redirect_uri, scopes)
        self.provider_name = "redir"


def _client(get_session, UserModel, response_mode: Literal["redirect", "json"]):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={
            "stub": OAuthCredentials(client_id="id", client_secret="sec"),
            "redir": OAuthCredentials(client_id="id", client_secret="sec"),
        },
        redirect_base_url="http://test",
        oauth_response_mode=response_mode,
        warn_on_memory_backend=False,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return auth, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.fixture(autouse=True)
def other_provider(monkeypatch):
    monkeypatch.setitem(OAuthProviderFactory._providers, "redir", OtherStubProvider)


@pytest.fixture(params=["redirect", "json"])
async def browser(request, get_session, UserModel):
    auth, client = _client(get_session, UserModel, request.param)
    await auth.initialize()
    async with client:
        yield request.param, client
    await auth.shutdown()


async def _start(client: httpx.AsyncClient, provider: str = "stub") -> str:
    response = await client.get(f"/oauth/{provider}/authorize", follow_redirects=False)
    target = response.json()["url"] if response.status_code == 200 else response.headers["location"]
    return parse_qs(urlparse(target).query)["state"][0]


async def _callback(
    client: httpx.AsyncClient, state: str, provider: str = "stub"
) -> httpx.Response:
    return await client.get(
        f"/oauth/{provider}/callback",
        params={"code": "abc", "state": state},
        follow_redirects=False,
    )


def _assert_refused(mode: str, response: httpx.Response) -> None:
    """Refused the same way per mode, and never with a session."""
    if mode == "redirect":
        assert response.status_code == 307
        assert response.headers["location"] == INVALID_STATE_LOCATION
    else:
        assert response.status_code == 400
        assert response.json() == JSON_DETAIL
    assert "session_id=" not in " ".join(response.headers.get_list("set-cookie"))


async def test_no_state_cookie(browser) -> None:
    """The callback was opened in a browser that never started the flow."""
    mode, client = browser
    state = await _start(client)
    client.cookies.clear()

    _assert_refused(mode, await _callback(client, state))


async def test_a_state_cookie_for_another_flow(browser) -> None:
    """The browser's cookie belongs to a different sign-in than the callback."""
    mode, client = browser
    await _start(client)

    _assert_refused(mode, await _callback(client, "state-from-another-flow"))


async def test_a_stored_state_that_is_gone(browser) -> None:
    """The callback is replayed after it was consumed, or after the state expired."""
    mode, client = browser
    state = await _start(client)
    first = await _callback(client, state)
    assert first.status_code in (200, 307)
    client.cookies.set("oauth_state", state)

    _assert_refused(mode, await _callback(client, state))


async def test_a_state_started_for_another_provider(browser) -> None:
    mode, client = browser
    state = await _start(client, provider="stub")

    _assert_refused(mode, await _callback(client, state, provider="redir"))


async def test_redirect_mode_clears_the_state_cookie(get_session, UserModel) -> None:
    auth, client = _client(get_session, UserModel, "redirect")
    await auth.initialize()
    async with client:
        await _start(client)
        response = await _callback(client, "state-from-another-flow")
    await auth.shutdown()

    cleared = [c for c in response.headers.get_list("set-cookie") if c.startswith("oauth_state=")]
    assert cleared
    assert "max-age=0" in cleared[0].lower()


async def test_an_unknown_provider_is_still_a_400(get_session, UserModel) -> None:
    """A malformed URL isn't a failed sign-in, so it isn't redirected."""
    auth, client = _client(get_session, UserModel, "redirect")
    await auth.initialize()
    async with client:
        response = await client.get("/oauth/nope/callback", params={"code": "abc", "state": "x"})
    await auth.shutdown()

    assert response.status_code == 400

"""GenericOIDCProvider: issuer validation, discovery, client auth, claim mapping."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from crudauth import CRUDAuth, CookieConfig, OAuthCredentials, SessionTransport
from crudauth.exceptions import BadRequestException
from crudauth.oauth import GenericOIDCProvider
from crudauth.oauth.providers.oidc import normalize_issuer

ISSUER = "https://idp.example.com/realms/main"

DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
    "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
}


class Calls(list):
    """Records every request a MockTransport served."""


def _transport(document: object = DISCOVERY, status: int = 200, calls: Calls | None = None):
    """An IdP that serves the discovery document, the token endpoint and userinfo."""

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(status, json=document)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "the-token", "token_type": "Bearer"})
        return httpx.Response(200, json={"sub": "kc-1"})

    return httpx.MockTransport(handler)


def _provider(**kwargs) -> GenericOIDCProvider:
    kwargs.setdefault("issuer", ISSUER)
    kwargs.setdefault("provider_name", "keycloak")
    return GenericOIDCProvider("id", "sec", "https://app.example.com/cb", **kwargs)


async def _discovered(document=DISCOVERY, **kwargs) -> GenericOIDCProvider:
    provider = _provider(transport=_transport(document), **kwargs)
    await provider.initialize()
    return provider


# --- issuer validation -------------------------------------------------------
@pytest.mark.parametrize(
    "issuer",
    [
        "http://idp.example.com",
        "ftp://idp.example.com",
        "idp.example.com",
        "https://idp.example.com?realm=main",
        "https://idp.example.com#frag",
        "",
        "   ",
    ],
)
def test_bad_issuers_are_rejected_at_construction(issuer: str) -> None:
    with pytest.raises(ValueError):
        _provider(issuer=issuer)


def test_plain_http_issuer_is_allowed_on_localhost() -> None:
    assert normalize_issuer("http://localhost:8080/realms/main") == (
        "http://localhost:8080/realms/main"
    )
    assert normalize_issuer("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"


def test_issuer_keeps_its_path_and_drops_the_trailing_slash() -> None:
    assert _provider(issuer=f"{ISSUER}/").issuer == ISSUER


# --- discovery ---------------------------------------------------------------
async def test_discovery_resolves_the_three_endpoints() -> None:
    provider = await _discovered()
    assert provider.authorize_endpoint == DISCOVERY["authorization_endpoint"]
    assert provider.token_endpoint == DISCOVERY["token_endpoint"]
    assert provider.userinfo_endpoint == DISCOVERY["userinfo_endpoint"]
    assert provider.discovery_document["jwks_uri"] == DISCOVERY["jwks_uri"]


async def test_discovery_is_fetched_from_the_well_known_path_under_the_issuer() -> None:
    calls = Calls()
    provider = _provider(transport=_transport(DISCOVERY, calls=calls))
    await provider.initialize()
    assert str(calls[0].url) == f"{ISSUER}/.well-known/openid-configuration"


async def test_discovery_runs_once() -> None:
    calls = Calls()
    provider = _provider(transport=_transport(DISCOVERY, calls=calls))
    await provider.initialize()
    await provider.initialize()
    assert len(calls) == 1


async def test_endpoints_passed_explicitly_skip_discovery() -> None:
    calls = Calls()
    provider = _provider(
        transport=_transport(DISCOVERY, calls=calls),
        authorize_endpoint="https://idp.example.com/a",
        token_endpoint="https://idp.example.com/t",
        userinfo_endpoint="https://idp.example.com/u",
    )
    await provider.initialize()
    assert calls == []
    assert provider.authorize_endpoint == "https://idp.example.com/a"


async def test_a_document_declaring_another_issuer_is_rejected() -> None:
    document = {**DISCOVERY, "issuer": "https://evil.example.com"}
    with pytest.raises(ValueError, match="issuer mismatch"):
        await _discovered(document)


async def test_a_document_without_an_issuer_is_rejected() -> None:
    document = {k: v for k, v in DISCOVERY.items() if k != "issuer"}
    with pytest.raises(ValueError, match="issuer mismatch"):
        await _discovered(document)


async def test_a_document_declaring_the_issuer_with_a_trailing_slash_is_accepted() -> None:
    provider = await _discovered({**DISCOVERY, "issuer": f"{ISSUER}/"})
    assert provider.token_endpoint == DISCOVERY["token_endpoint"]


async def test_a_document_missing_an_endpoint_is_rejected() -> None:
    document = {k: v for k, v in DISCOVERY.items() if k != "token_endpoint"}
    with pytest.raises(ValueError, match="token_endpoint"):
        await _discovered(document)


async def test_a_document_that_is_not_an_object_is_rejected() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        await _discovered(["not", "a", "document"])


async def test_a_failing_discovery_request_raises() -> None:
    provider = _provider(transport=_transport(DISCOVERY, status=404))
    with pytest.raises(httpx.HTTPStatusError):
        await provider.initialize()


# --- an unresolved provider refuses to serve ---------------------------------
async def test_an_unresolved_provider_raises_instead_of_using_empty_endpoints() -> None:
    provider = _provider()
    with pytest.raises(RuntimeError, match="initialize"):
        provider.get_authorization_url()
    with pytest.raises(RuntimeError, match="initialize"):
        await provider.exchange_code("code")
    with pytest.raises(RuntimeError, match="initialize"):
        await provider.get_user_info("token")


async def test_the_authorization_url_uses_the_discovered_endpoint_with_pkce() -> None:
    provider = await _discovered()
    result = provider.get_authorization_url()
    assert result["url"].startswith(f"{DISCOVERY['authorization_endpoint']}?")
    params = parse_qs(urlparse(result["url"]).query)
    assert params["code_challenge_method"] == ["S256"]
    assert params["scope"] == ["openid profile email"]
    assert result["code_verifier"]


# --- token-endpoint client authentication ------------------------------------
async def _token_request(document: dict, client_secret: str = "sec") -> httpx.Request:
    calls = Calls()
    provider = GenericOIDCProvider(
        "id",
        client_secret,
        "https://app.example.com/cb",
        issuer=ISSUER,
        transport=_transport(document, calls=calls),
    )
    await provider.initialize()
    await provider.exchange_code("the-code", code_verifier="v")
    return calls[-1]


async def test_the_secret_rides_in_the_body_when_the_provider_takes_post() -> None:
    request = await _token_request(DISCOVERY)
    assert "authorization" not in request.headers
    assert b"client_secret=sec" in request.content


async def test_basic_auth_is_used_when_the_provider_only_advertises_it() -> None:
    document = {**DISCOVERY, "token_endpoint_auth_methods_supported": ["client_secret_basic"]}
    request = await _token_request(document)
    assert request.headers["authorization"].startswith("Basic ")
    assert b"client_secret" not in request.content


async def test_a_public_client_sends_no_client_authentication() -> None:
    document = {**DISCOVERY, "token_endpoint_auth_methods_supported": ["client_secret_basic"]}
    request = await _token_request(document, client_secret="")
    assert "authorization" not in request.headers
    assert b"client_secret" not in request.content


# --- claim mapping -----------------------------------------------------------
async def test_standard_claims_map_through() -> None:
    provider = await _discovered()
    info = await provider.process_user_info(
        {
            "sub": "kc-1",
            "email": "u@x.com",
            "email_verified": True,
            "preferred_username": "user1",
            "name": "User One",
            "given_name": "User",
            "family_name": "One",
            "picture": "https://idp.example.com/p.png",
        }
    )
    assert info.provider == "keycloak"
    assert info.provider_user_id == "kc-1"
    assert info.email == "u@x.com"
    assert info.email_verified is True
    assert info.username == "user1"
    assert info.name == "User One"
    assert info.given_name == "User"
    assert info.family_name == "One"
    assert info.picture == "https://idp.example.com/p.png"


@pytest.mark.parametrize("claim", ["true", 1, None, "yes"])
async def test_email_verified_is_only_true_for_the_boolean(claim: object) -> None:
    provider = await _discovered()
    info = await provider.process_user_info({"sub": "kc-1", "email_verified": claim})
    assert info.email_verified is False


async def test_a_numeric_subject_is_stringified() -> None:
    provider = await _discovered()
    info = await provider.process_user_info({"sub": 42})
    assert info.provider_user_id == "42"


@pytest.mark.parametrize("user_info", [{}, {"sub": None}, {"sub": ""}])
async def test_a_response_without_a_subject_is_an_error(user_info: dict) -> None:
    provider = await _discovered()
    with pytest.raises(BadRequestException, match="sub"):
        await provider.process_user_info(user_info)


# --- configured through oauth={...} ------------------------------------------
@pytest.fixture
async def oidc_app(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"oidc": OAuthCredentials(client_id="id", client_secret="sec", issuer=ISSUER)},
        redirect_base_url="http://test",
    )
    auth.oauth_providers["oidc"].transport = _transport(DISCOVERY)
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield auth, client
    await auth.shutdown()


async def test_an_issuer_in_the_credentials_builds_an_oidc_provider(oidc_app) -> None:
    auth, _ = oidc_app
    provider = auth.oauth_providers["oidc"]
    assert isinstance(provider, GenericOIDCProvider)
    assert provider.redirect_uri == "http://test/oauth/oidc/callback"
    assert provider.token_endpoint == DISCOVERY["token_endpoint"]


async def test_authorize_redirects_to_the_discovered_endpoint(oidc_app) -> None:
    _, client = oidc_app
    response = await client.get("/oauth/oidc/authorize", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"].startswith(f"{DISCOVERY['authorization_endpoint']}?")
    params = parse_qs(urlparse(response.headers["location"]).query)
    assert params["client_id"] == ["id"]
    assert params["redirect_uri"] == ["http://test/oauth/oidc/callback"]


async def test_a_provider_without_its_id_column_is_a_startup_error(get_session, UserModel) -> None:
    with pytest.raises(ValueError, match="keycloak_id"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport()],
            oauth={"keycloak": OAuthCredentials(client_id="id", issuer=ISSUER)},
            redirect_base_url="http://test",
        )

"""Generic OpenID Connect provider, configured from an issuer via discovery.

Google and GitHub hardcode their endpoints. Every other spec-compliant provider
(Keycloak, Zitadel, Authentik, Auth0, Okta, Entra ID, ...) describes itself in the
discovery document at ``{issuer}/.well-known/openid-configuration``, so the only
thing an app has to supply is the issuer and its client credentials.

Discovery is a network call, and the port's authorization-URL surface is sync, so
the fetch happens in [initialize][crudauth.oauth.providers.oidc.GenericOIDCProvider.initialize],
which [CRUDAuth.initialize][crudauth.crud_auth.CRUDAuth.initialize] awaits at
startup. Until then the endpoints are unresolved and any use of them raises.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ...exceptions import BadRequestException
from ..constants import (
    OAUTH_HTTP_TIMEOUT_SECONDS,
    OIDC_DEFAULT_SCOPES,
    OIDC_DISCOVERY_PATH,
    OIDC_LOCAL_HOSTS,
    TOKEN_AUTH_BASIC,
    TOKEN_AUTH_POST,
)
from ..provider import AbstractOAuthProvider, _require_httpx
from ..schemas import OAuthUserInfo

__all__ = ["GenericOIDCProvider", "normalize_issuer"]

_REQUIRED_ENDPOINTS = ("authorization_endpoint", "token_endpoint", "userinfo_endpoint")


def normalize_issuer(issuer: str) -> str:
    """Validate an OIDC issuer and return it without its trailing slash.

    Rejects anything that can't be an issuer identifier: a non-HTTPS scheme
    (except on localhost, for development), and a URL carrying a query string or
    fragment. The issuer is the value the discovery document must declare back,
    so it has to be compared as an exact string; normalizing here means the
    comparison isn't guessing what the caller meant.

    Raises:
        ValueError: The issuer is empty, not HTTP(S), non-HTTPS off localhost, or
            carries a query or fragment.
    """
    if not issuer or not issuer.strip():
        raise ValueError("OAuthCredentials.issuer cannot be empty.")
    parts = urlsplit(issuer.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"OIDC issuer must be an absolute http(s) URL, got {issuer!r}.")
    if parts.query or parts.fragment:
        raise ValueError(f"OIDC issuer cannot carry a query or fragment, got {issuer!r}.")
    if parts.scheme == "http" and parts.hostname not in OIDC_LOCAL_HOSTS:
        raise ValueError(
            f"OIDC issuer {issuer!r} must use https (plain http is allowed only on "
            f"{', '.join(sorted(OIDC_LOCAL_HOSTS))}, for local development)."
        )
    return issuer.strip().rstrip("/")


class GenericOIDCProvider(AbstractOAuthProvider):
    """An OIDC provider whose endpoints come from its issuer's discovery document.

    Configure it through ``oauth=`` by giving the credentials an issuer:

    Example:
        ```python
        auth = CRUDAuth(
            ...,
            oauth={
                "keycloak": OAuthCredentials(
                    client_id="...",
                    client_secret="...",
                    issuer="https://sso.example.com/realms/main",
                )
            },
            redirect_base_url="https://app.example.com",
        )
        ```

    The key you use is the provider name, so it's also the column the account is
    linked on (``keycloak`` -> ``keycloak_id``) and the path segment in
    ``/oauth/keycloak/authorize``. ``process_user_info`` reads the standard OIDC
    claims, which every conformant provider returns from ``/userinfo``.

    Note:
        The provider is unusable until ``initialize()`` has resolved the
        endpoints. ``CRUDAuth.initialize()`` does that, which is the same
        lifespan call Redis-backed storage already needs.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        issuer: str,
        provider_name: str = "oidc",
        scopes: list[str] | None = None,
        authorize_endpoint: str = "",
        token_endpoint: str = "",
        userinfo_endpoint: str = "",
        transport: Any | None = None,
    ):
        """Build an unresolved provider; ``initialize()`` fills in the endpoints.

        Args:
            issuer: The provider's issuer identifier, e.g.
                ``https://sso.example.com/realms/main``. A trailing slash is ignored.
            provider_name: The linked-account name, so ``"keycloak"`` stores its
                account id in ``keycloak_id``.
            scopes: Override the default ``openid profile email``.
            authorize_endpoint: Skip discovery for this endpoint by passing it
                (along with the other two) explicitly.
            token_endpoint: See ``authorize_endpoint``.
            userinfo_endpoint: See ``authorize_endpoint``.
            transport: An ``httpx`` transport for every outbound call, for a proxy,
                a client certificate, or a test double.
        """
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=scopes or list(OIDC_DEFAULT_SCOPES),
            authorize_endpoint=authorize_endpoint,
            token_endpoint=token_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            provider_name=provider_name,
            transport=transport,
        )
        self.issuer = normalize_issuer(issuer)
        self.discovery_document: dict[str, Any] = {}
        self._resolved = all((authorize_endpoint, token_endpoint, userinfo_endpoint))

    @classmethod
    async def from_discovery(
        cls,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        provider_name: str = "oidc",
        scopes: list[str] | None = None,
        transport: Any | None = None,
    ) -> GenericOIDCProvider:
        """Build a provider and resolve its endpoints in one await.

        For code that owns its providers directly (a hand-written OAuth route, a
        script). Through ``oauth=`` you don't need this: ``CRUDAuth`` constructs
        the provider and ``initialize()`` resolves it.
        """
        provider = cls(
            client_id,
            client_secret,
            redirect_uri,
            issuer=issuer,
            provider_name=provider_name,
            scopes=scopes,
            transport=transport,
        )
        await provider.initialize()
        return provider

    async def initialize(self) -> None:
        """Fetch the discovery document and resolve the endpoints (idempotent).

        Raises:
            ValueError: The document is missing a required endpoint, or declares
                an issuer other than the configured one.
            httpx.HTTPStatusError: The discovery endpoint returned an error status.
        """
        if self._resolved:
            return
        httpx = _require_httpx()
        url = f"{self.issuer}{OIDC_DISCOVERY_PATH}"
        async with httpx.AsyncClient(
            timeout=OAUTH_HTTP_TIMEOUT_SECONDS, transport=self.transport
        ) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
            document = response.json()
        if not isinstance(document, dict):
            raise ValueError(f"OIDC discovery at {url} did not return a JSON object.")

        declared = str(document.get("issuer", ""))
        if declared != self.issuer and declared.rstrip("/") != self.issuer:
            raise ValueError(
                f"OIDC discovery issuer mismatch: configured {self.issuer!r}, document "
                f"declares {declared!r}. The document must declare the issuer it was "
                "fetched from; a mismatch means the wrong provider answered."
            )
        missing = [key for key in _REQUIRED_ENDPOINTS if not document.get(key)]
        if missing:
            raise ValueError(f"OIDC discovery at {url} is missing {missing}.")

        self.authorize_endpoint = document["authorization_endpoint"]
        self.token_endpoint = document["token_endpoint"]
        self.userinfo_endpoint = document["userinfo_endpoint"]
        self.token_auth_method = self._pick_token_auth(document)
        self.discovery_document = document
        self._resolved = True

    def _pick_token_auth(self, document: dict[str, Any]) -> str:
        """Pick the client authentication the provider actually accepts at the token endpoint.

        ``client_secret_post`` (credentials in the form body) is what the base
        provider sends and what most providers accept. A provider that advertises
        only ``client_secret_basic`` - Entra ID's v1 endpoints, some Keycloak
        client setups - rejects that, so this switches to HTTP Basic. A public
        client sends no credentials either way.
        """
        supported = document.get("token_endpoint_auth_methods_supported")
        if not self.client_secret or not isinstance(supported, list):
            return TOKEN_AUTH_POST
        if TOKEN_AUTH_POST in supported:
            return TOKEN_AUTH_POST
        if TOKEN_AUTH_BASIC in supported:
            return TOKEN_AUTH_BASIC
        return TOKEN_AUTH_POST

    def _ensure_ready(self) -> None:
        if not self._resolved:
            raise RuntimeError(
                f"The {self.provider_name!r} OIDC provider hasn't resolved its endpoints yet. "
                "Await auth.initialize() in your app's lifespan startup, before serving."
            )

    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        """Normalize the standard OIDC userinfo claims into ``OAuthUserInfo``.

        ``sub`` is the account's stable identifier, so a response without one is
        an error rather than a user linked to the string ``"None"``.
        ``email_verified`` is passed through as the provider stated it: a
        verified provider email is what lets the callback link the profile to an
        existing local account, so a provider that doesn't claim verification
        doesn't get that.
        """
        subject = user_info.get("sub")
        if subject is None or str(subject) == "":
            raise BadRequestException(f"{self.provider_name} did not return a subject (sub).")
        return OAuthUserInfo(
            provider=self.provider_name,
            provider_user_id=str(subject),
            email=user_info.get("email"),
            email_verified=user_info.get("email_verified") is True,
            name=user_info.get("name"),
            given_name=user_info.get("given_name"),
            family_name=user_info.get("family_name"),
            username=user_info.get("preferred_username"),
            picture=user_info.get("picture"),
            raw_data=user_info,
        )

"""``AbstractOAuthProvider`` - the port you subclass to add a provider.

Implements the generic Authorization-Code-with-PKCE dance; concrete providers
only supply endpoints and a ``process_user_info`` mapping.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlencode

from .constants import (
    OAUTH_HTTP_TIMEOUT_SECONDS,
    PKCE_VERIFIER_BYTES,
    STATE_BYTES,
    TOKEN_AUTH_BASIC,
    TOKEN_AUTH_POST,
)
from .schemas import OAuthUserInfo

__all__ = ["AbstractOAuthProvider"]


def _require_httpx():
    try:
        import httpx  # noqa: F401

        return httpx
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "OAuth requires the 'httpx' package. Install with: pip install 'crudauth[oauth]'"
        ) from exc


class AbstractOAuthProvider(ABC):
    """Port for an OAuth provider - implements the Authorization-Code-with-PKCE flow.

    Subclass it, pass the three endpoints + scopes + ``provider_name`` to
    ``super().__init__``, implement [process_user_info][crudauth.oauth.provider.AbstractOAuthProvider.process_user_info], and register it
    with [OAuthProviderFactory][crudauth.oauth.factory.OAuthProviderFactory]. Set ``email_verified`` honestly -
    auto-linking to an existing account requires a verified provider email.

    Set ``requires_client_secret = True`` on a provider that never accepts a
    public client, so a missing secret fails at startup instead of at the first
    login.

    Note:
        A custom provider named ``"gitlab"`` requires a ``gitlab_id`` column on
        your user model (that's where its account id is stored and matched). Add
        it to your model (or map it via ``column_map=``); [CRUDAuth][crudauth.crud_auth.CRUDAuth]
        raises at startup if a configured provider has no ``{provider}_id``
        column. Only ``google_id``/``github_id`` ship on
        [AuthUserMixin][crudauth.models.mixin.AuthUserMixin].

    Example:
        ```python
        class GitLabOAuthProvider(AbstractOAuthProvider):
            def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
                super().__init__(
                    client_id, client_secret, redirect_uri,
                    scopes=scopes or ["read_user"],
                    authorize_endpoint="https://gitlab.com/oauth/authorize",
                    token_endpoint="https://gitlab.com/oauth/token",
                    userinfo_endpoint="https://gitlab.com/api/v4/user",
                    provider_name="gitlab",
                )

            async def process_user_info(self, info):
                return OAuthUserInfo(
                    provider="gitlab", provider_user_id=str(info["id"]),
                    email=info.get("email"), email_verified=True, raw_data=info,
                )

        OAuthProviderFactory.register_provider("gitlab", GitLabOAuthProvider)
        # ...and add `gitlab_id` to your user model.
        ```
    """

    requires_client_secret: bool = False
    token_auth_method: str = TOKEN_AUTH_POST

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        scopes: list[str],
        authorize_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str,
        provider_name: str,
        transport: Any | None = None,
    ):
        if self.requires_client_secret and not client_secret:
            raise ValueError(
                f"The {provider_name!r} OAuth provider needs a client_secret: "
                "set OAuthCredentials(client_secret=...)."
            )
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.authorize_endpoint = authorize_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.provider_name = provider_name
        self.transport = transport

    # --- lifecycle -----------------------------------------------------------
    async def initialize(self) -> None:
        """Resolve whatever the provider needs before it can serve a login.

        A no-op for a provider with static endpoints.
        [CRUDAuth.initialize][crudauth.crud_auth.CRUDAuth.initialize] awaits this
        for every configured provider, so a provider that discovers its endpoints
        can do it there.
        """
        return None

    def _ensure_ready(self) -> None:
        """Raise if the provider isn't usable yet; called before every outbound step."""
        return None

    # --- PKCE / state --------------------------------------------------------
    @staticmethod
    def generate_state() -> str:
        """Return a fresh, URL-safe CSRF ``state`` value."""
        return secrets.token_urlsafe(STATE_BYTES)

    @staticmethod
    def generate_pkce_codes() -> dict[str, str]:
        """Return a PKCE pair: ``{"code_verifier": ..., "code_challenge": ...}`` (S256)."""
        verifier = secrets.token_urlsafe(PKCE_VERIFIER_BYTES)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return {"code_verifier": verifier, "code_challenge": challenge}

    # --- authorization URL ---------------------------------------------------
    def get_authorization_url(
        self,
        state: str | None = None,
        pkce: bool = True,
        extra_params: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Build the provider authorization URL and the values to stash server-side.

        Args:
            state: CSRF state to embed; generated if omitted.
            pkce: Include a PKCE challenge (recommended).
            extra_params: Provider-specific query params to merge in (e.g. Google's
                ``access_type``/``prompt``).

        Returns:
            ``{"url": <redirect target>, "state": ..., "code_verifier": ...}`` -
            ``code_verifier`` is present only when ``pkce`` is true and must be
            persisted to verify the callback.
        """
        self._ensure_ready()
        state = state or self.generate_state()
        params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.scopes),
        }
        result: dict[str, str] = {"state": state}
        if pkce:
            codes = self.generate_pkce_codes()
            params["code_challenge"] = codes["code_challenge"]
            params["code_challenge_method"] = "S256"
            result["code_verifier"] = codes["code_verifier"]
        if extra_params:
            params.update(extra_params)
        result["url"] = f"{self.authorize_endpoint}?{urlencode(params)}"
        return result

    # --- token exchange ------------------------------------------------------
    async def exchange_code(
        self,
        code: str,
        code_verifier: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Exchange an authorization ``code`` for tokens at the token endpoint.

        Args:
            code: The authorization code from the callback.
            code_verifier: The stored PKCE verifier (required if PKCE was used).
            headers: Extra request headers (some providers need ``Accept``).

        Returns:
            The provider's raw token response (``access_token``, ...).

        Raises:
            httpx.HTTPStatusError: If the token endpoint returns an error status.

        Note:
            ``client_secret`` is sent only when set, so a public client (PKCE
            only) sends no client authentication. It rides in the form body
            (``client_secret_post``) unless ``token_auth_method`` says the
            provider wants HTTP Basic (``client_secret_basic``).
        """
        self._ensure_ready()
        httpx = _require_httpx()
        data = {
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        auth = None
        if self.client_secret and self.token_auth_method == TOKEN_AUTH_BASIC:
            auth = (self.client_id, self.client_secret)
        elif self.client_secret:
            data["client_secret"] = self.client_secret
        if code_verifier:
            data["code_verifier"] = code_verifier
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        async with httpx.AsyncClient(
            timeout=OAUTH_HTTP_TIMEOUT_SECONDS, transport=self.transport
        ) as client:
            resp = await client.post(self.token_endpoint, data=data, headers=req_headers, auth=auth)
            resp.raise_for_status()
            return resp.json()

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """Fetch the raw user profile from the userinfo endpoint.

        Args:
            access_token: A valid provider access token.

        Returns:
            The provider's raw profile JSON (normalize it in
            [process_user_info][crudauth.oauth.provider.AbstractOAuthProvider.process_user_info]).

        Raises:
            httpx.HTTPStatusError: If the userinfo endpoint returns an error status.
        """
        self._ensure_ready()
        httpx = _require_httpx()
        async with httpx.AsyncClient(
            timeout=OAUTH_HTTP_TIMEOUT_SECONDS, transport=self.transport
        ) as client:
            resp = await client.get(
                self.userinfo_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            return resp.json()

    @abstractmethod
    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        """Normalize the provider's raw user payload into [OAuthUserInfo][crudauth.oauth.schemas.OAuthUserInfo]."""
        raise NotImplementedError

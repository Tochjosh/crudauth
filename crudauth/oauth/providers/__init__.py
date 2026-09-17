"""Built-in OAuth providers (Google, GitHub), registered on import."""

from __future__ import annotations

from ..constants import GITHUB, GOOGLE
from ..factory import OAuthProviderFactory
from .github import GitHubOAuthProvider
from .google import GoogleOAuthProvider
from .oidc import GenericOIDCProvider

OAuthProviderFactory.register_provider(GOOGLE, GoogleOAuthProvider)
OAuthProviderFactory.register_provider(GITHUB, GitHubOAuthProvider)

# GenericOIDCProvider is deliberately not registered with the factory: it's
# selected by OAuthCredentials(issuer=...), not by name, and the factory builds
# from a name alone.

__all__ = ["GoogleOAuthProvider", "GitHubOAuthProvider", "GenericOIDCProvider"]

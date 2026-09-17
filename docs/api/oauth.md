# OAuth

OAuth 2.0 social login. Enable it with `oauth={...}` on [CRUDAuth](crud-auth.md). An OpenID
Connect provider needs only `OAuthCredentials(issuer=...)`, which configures
`GenericOIDCProvider`; anything else is added by implementing `AbstractOAuthProvider` and
registering it with `OAuthProviderFactory`.

::: crudauth.oauth.OAuthCredentials

::: crudauth.oauth.OAuthUserInfo

::: crudauth.oauth.GenericOIDCProvider

::: crudauth.oauth.AbstractOAuthProvider

::: crudauth.oauth.OAuthProviderFactory

::: crudauth.oauth.OAuthAccountService

# OAuth

OAuth lets users sign in with Google, GitHub, or a custom provider. CRUDAuth runs the
authorization-code flow, links the result to a user in your database, and establishes a
session on the callback.

```python
from crudauth import CRUDAuth, SessionTransport, OAuthCredentials

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    redirect_base_url="https://app.example.com",
    transports=[SessionTransport()],
    oauth={
        "google": OAuthCredentials(client_id="...", client_secret="..."),
        "github": OAuthCredentials(client_id="...", client_secret="..."),
    },
)
```

OAuth establishes a session on the callback, so it requires a `SessionTransport` and a
`redirect_base_url`. Each provider also needs a `{provider}_id` column on your user model
(`google_id`, `github_id`, ...) to store and match the account; `AuthUserMixin` includes the
built-in ones.

This adds two routes per provider: `GET /oauth/{provider}/authorize` (start the flow) and
`GET /oauth/{provider}/callback` (finish it). The redirect URI you register with the provider
is `{redirect_base_url}/oauth/{provider}/callback`. Both the paths and the response format are
configurable; see [Custom paths and JSON responses](#custom-paths-and-json-responses).

## The flow

<p align="center">
  <img src="../../assets/diagrams/oauth-flow-light.png#only-light" alt="The four-step OAuth authorization-code flow: your app redirects out with a state, the provider signs the user in, the callback returns a code and state which CRUDAuth rechecks, then CRUDAuth exchanges the code, links the user, and logs them in" width="100%">
  <img src="../../assets/diagrams/oauth-flow-dark.png#only-dark" alt="The four-step OAuth authorization-code flow: your app redirects out with a state, the provider signs the user in, the callback returns a code and state which CRUDAuth rechecks, then CRUDAuth exchanges the code, links the user, and logs them in" width="100%">
</p>

CRUDAuth binds the `state` parameter to the initiating browser via a cookie, so a stolen or
forged callback can't complete someone else's login. The redirect target after login is
validated against an allowlist to prevent open redirects.

For hand-written post-login or post-logout redirects, reuse
[`safe_redirect_path`](../../api/utils.md) rather than accepting a client-supplied URL
directly. It accepts only single-slash relative paths and falls back to `/` by default.

## Account linking

On a successful callback, CRUDAuth finds or creates the user:

- If a user already exists with the provider's verified email, the provider account is linked
  to it (the `{provider}_id` column is set). The user can then sign in by password or by that
  provider.
- Otherwise a new user is created from the provider profile. To set your own columns on that
  user (a required `name`, a default tier), use `new_user_fields` / `new_user_defaults`, which
  run on this path too; see [Registration](../accounts/registration.md#setting-columns-the-server-controls).

This linking logic lives in `auth.oauth` (an `OAuthAccountService`, or `None` when OAuth isn't
configured), so a hand-written callback can reuse it:
`user, created = await auth.oauth.get_or_create_user(info, db)`. See
[Use the building blocks](../../cookbook/use-the-building-blocks.md).

## Custom providers

Add a provider by implementing the `AbstractOAuthProvider` port and registering it with
`OAuthProviderFactory`, then pass its credentials in `oauth={...}` like the built-ins. See
the [OAuth reference](../../api/oauth.md) for the port and factory.

## Custom paths and JSON responses

`oauth_paths` moves the routes. Both paths must contain `{provider}`:

```python
auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    redirect_base_url="https://app.example.com",
    transports=[SessionTransport()],
    oauth={"google": OAuthCredentials(client_id="...", client_secret="...")},
    oauth_paths={
        "prefix": "/api/v1/auth/oauth",
        "authorize_path": "/{provider}",
        "callback_path": "/callback/{provider}",
    },
)
```

The redirect URI follows the same paths, here
`https://app.example.com/api/v1/auth/oauth/callback/google`. CRUDAuth doesn't see a prefix
you add when mounting (`app.include_router(auth.router, prefix="/api")`), so include that
prefix in `redirect_base_url` as well.

`auth.oauth_router` returns only the OAuth routes, for apps that mount their own auth routes
instead of `auth.router`. Mount one or the other, not both.

`oauth_response_mode="json"` is for single-page and mobile clients:

- `authorize` returns `{"url": ...}` instead of redirecting, and still sets the state cookie.
  The client then sends the browser to that URL.
- `callback` returns `{"user": ..., "csrf_token": ..., "redirect_to": ...}` with the session
  cookies set. `user` has the same fields as `/me`. A failed callback returns `400` with
  `{"detail": "oauth_failed"}` instead of redirecting.

The provider still sends the browser to the redirect URI, so in JSON mode that URI should be a
frontend page: point `redirect_base_url` at the frontend, serve the callback path there, and
have that page call the API's callback with the same `code` and `state`, using
`fetch(url, {credentials: "include"})`. Call `authorize` with credentials too, so the browser
keeps the state cookie. That cookie is `SameSite=Lax`, so the frontend and the API must be on
the same site (for example `app.example.com` and `api.example.com`); a cross-site request
doesn't send it and the callback returns `400`.

---

[Next: Sudo mode →](sudo.md){ .md-button .md-button--primary }

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

CRUDAuth always uses PKCE. For a public client (one your identity provider registers without a
secret), leave out `client_secret`: `OAuthCredentials(client_id="...")`. The token request then
carries no client authentication, which providers configured for public clients expect. Google and
GitHub always need a secret for a server-side callback, so they raise at startup without one.

## The flow

<p align="center">
  <img src="../../assets/diagrams/oauth-flow-light.png#only-light" alt="The four-step OAuth authorization-code flow: your app redirects out with a state, the provider signs the user in, the callback returns a code and state which CRUDAuth rechecks, then CRUDAuth exchanges the code, links the user, and logs them in" width="100%">
  <img src="../../assets/diagrams/oauth-flow-dark.png#only-dark" alt="The four-step OAuth authorization-code flow: your app redirects out with a state, the provider signs the user in, the callback returns a code and state which CRUDAuth rechecks, then CRUDAuth exchanges the code, links the user, and logs them in" width="100%">
</p>

CRUDAuth binds the `state` parameter to the initiating browser via a cookie, so a stolen or
forged callback can't complete someone else's login. The redirect target after login must be
a same-origin relative path; anything else falls back to the default, which prevents open
redirects.

For hand-written post-login or post-logout redirects, reuse
[`safe_redirect_path`](../../api/utils.md) rather than accepting a client-supplied URL
directly. It accepts only single-slash relative paths and falls back to `/` by default.

## Account linking

On a successful callback, CRUDAuth finds or creates the user. A returning provider account signs
in to the user it's linked to. Otherwise the provider must report a verified email, or the sign-in
fails with `email_unverified`:

- If a user already exists with that email, the provider account is linked to it (the
  `{provider}_id` column is set), and the user can sign in by password or by that provider. If that
  user never verified its email, whoever registered it hasn't proven they own the address, so the
  link also claims the account: the password becomes unusable, `token_version` is bumped, every
  session is signed out, and the email is marked verified. The owner can set a password again with
  a password reset. A user already linked to a different account of the same provider isn't
  relinked (`provider_already_linked`).
- Otherwise a new user is created from the provider profile. Its username comes from the
  provider's username, given name, display name, or email local-part, reduced to lowercase
  letters, digits, and single underscores, and cut to your `username` column's length (32 when
  the column has no length). A taken username gets `_1`, `_2`, ... and then a random suffix,
  still within that length. A provider email longer than your `email` column fails the sign-in
  (`email_too_long`) instead of reaching the insert. To set your own columns on that user (a required
  `name`, a default tier), use `new_user_fields` / `new_user_defaults`, which run on this path too; see
  [Registration](../accounts/registration.md#setting-columns-the-server-controls).

A disabled user (`is_active` false) gets no session: the callback fails with `account_inactive`.

This linking logic lives in `auth.oauth` (an `OAuthAccountService`, or `None` when OAuth isn't
configured), so a hand-written callback can reuse it:
`user, created = await auth.oauth.get_or_create_user(info, db)`. It raises
[`OAuthAccountException`](../../api/exceptions.md) with the error code in `code`. See
[Use the building blocks](../../cookbook/use-the-building-blocks.md).

## Errors

A failed callback redirects to `redirect_base_url` with `?error=<code>`, or returns `400` with
`{"detail": "<code>"}` in JSON mode:

| Code | Meaning |
|------|---------|
| `oauth_failed` | The provider reported an error or the user declined, the callback was malformed, or the token exchange or profile request failed. |
| `email_missing` | The provider account has no email address. |
| `email_unverified` | The provider reports the email as unverified. |
| `email_too_long` | The email is longer than your `email` column. |
| `provider_already_linked` | The matching user is linked to a different account of this provider. |
| `account_inactive` | The user is disabled. |

A callback whose `state` doesn't match the browser's state cookie returns `400` in both modes.
The state is used up either way, so a retry starts again from `authorize`.

`GET /oauth/{provider}/authorize` stores a state entry per request, so it's rate limited per IP
(`oauth_authorize`, 30 per hour by default; tune it with `rate_limits=`).

## Custom providers

Add a provider by implementing the `AbstractOAuthProvider` port and registering it with
`OAuthProviderFactory`, then pass its credentials in `oauth={...}` like the built-ins. Set
`requires_client_secret = True` on the class if the provider never accepts a public client, so a
missing secret fails at startup instead of at the first login. See the
[OAuth reference](../../api/oauth.md) for the port and factory.

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
  `{"detail": "<code>"}` instead of redirecting (see [Errors](#errors)).

The provider still sends the browser to the redirect URI, so in JSON mode that URI should be a
frontend page: point `redirect_base_url` at the frontend, serve the callback path there, and
have that page call the API's callback with the same `code` and `state`, using
`fetch(url, {credentials: "include"})`. Call `authorize` with credentials too, so the browser
keeps the state cookie. That cookie is `SameSite=Lax`, so the frontend and the API must be on
the same site (for example `app.example.com` and `api.example.com`); a cross-site request
doesn't send it and the callback returns `400`.

---

[Next: Sudo mode →](sudo.md){ .md-button .md-button--primary }

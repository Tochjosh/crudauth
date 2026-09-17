# Account & device management

Most apps grow a settings page: "where am I signed in," sign out a single device, sign out
everywhere, change my password. crudauth ships these as opt-in routes, so you wire buttons to them
instead of hand-writing session bookkeeping, CSRF refresh, and an in-session password change. The
security parts (CSRF, ownership checks, session eviction) are already handled.

This recipe assumes the [email and password](email-password.md) base (a session transport, a mounted
router).

## 1. Turn the routes on

The session and CSRF routes are opt-in; flip `management_routes=True` on the `SessionTransport`.
`/change-password` is always present (it's a core flow), so it needs no flag.

```python title="main.py"
from crudauth import CRUDAuth, SessionTransport
from myapp.db import get_session
from myapp.models import User

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[SessionTransport(management_routes=True)],
)
app.include_router(auth.router)
```

That mounts `GET /sessions`, `DELETE /sessions/{id}`, `POST /logout-all`, and `POST /csrf/refresh`,
alongside the always-on `POST /change-password`.

## 2. The device list

`GET /sessions` returns one entry per active session, with parsed device info and a `current` flag
for the calling session, so a "your devices" table is a single fetch:

```bash
curl http://localhost:8000/sessions -b jar.txt
# [{"id":"...","device":{"browser":"Chrome","os":"macOS",...},
#   "ip":"...","created_at":"...","last_activity":"...","current":true}, ...]
```

`id` is a handle for the session, not the session id itself: the session id is the cookie value,
so returning it would hand a stolen response every device's login. `DELETE /sessions/{id}` takes
the handle.

## 3. Revoke a device, or sign out everywhere

`DELETE /sessions/{id}` revokes one session; it's ownership-checked, so a user can only drop their
own, and an id that isn't theirs (or doesn't exist) is a `404` with no leak. `POST /logout-all` drops
them all, with `?keep_current=true` for the common "sign out my other devices":

```bash
# revoke one device (CSRF header required on the unsafe verb)
curl -X DELETE http://localhost:8000/sessions/<id> -b jar.txt -H "X-CSRF-Token: <token>"

# sign out everywhere except here
curl -X POST "http://localhost:8000/logout-all?keep_current=true" -b jar.txt -H "X-CSRF-Token: <token>"
# {"detail": "Signed out of all sessions.", "revoked": 3}
```

Revoking your own current session (or `/logout-all` without `keep_current`) clears the session
cookies on the way out.

## 4. Change a password

`POST /change-password` verifies the current password and sets the new one. The current password is
the re-authentication, so there's no email round-trip:

```bash
curl -X POST http://localhost:8000/change-password -b jar.txt -H "X-CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"old-one","new_password":"a-new-strong-one"}'
```

A wrong current password is `401`; an OAuth-only account (no usable password) is `400` and should use
[`/set-password`](../guides/accounts/passwords.md#setting-a-password-on-an-oauth-only-account). A
successful change is treated as a compromise response: it bumps `token_version` (evicting bearer
tokens) and revokes the user's *other* sessions, keeping the current one, and fires the
`on_after_password_changed` hook (a good place for a "your password was changed" email).

## 5. Self-heal a lost CSRF cookie

An SPA can lose its CSRF cookie (a cleared cookie jar, a stale tab) while the session cookie is still
valid, which would make every mutation fail. `POST /csrf/refresh` re-mints it:

```bash
curl -X POST http://localhost:8000/csrf/refresh -b jar.txt
# {"csrf_token": "..."}  (+ a fresh CSRF cookie)
```

It deliberately doesn't require a CSRF header (that would defeat the recovery), resolves the session
cookie directly, and self-heals: if the current CSRF cookie is already valid it returns it unchanged
rather than rotating. An attacker can trigger it cross-origin but can't read the response (CORS), so
they never learn the token.

## Why this is safe to expose

Each route is thin: authenticate, validate, call an existing `SessionManager` method. The dangerous
parts are handled for you, not left to your handler. CSRF is enforced on the unsafe verbs because they
sit behind a session principal (the one recovery exception, `/csrf/refresh`, is documented above).
`DELETE /sessions/{id}` is ownership-checked and returns `404` for both "not found" and "not yours,"
so it can't be used to probe other users' session ids. And a password change evicts other credentials
while keeping the caller signed in. You wire the buttons; the invariants come with the routes.

## Where to go next

- The manual approach (build your own routes over `auth.sessions`): [Devices & sessions](../guides/accounts/session-management.md).
- The password flows in full: [Passwords](../guides/accounts/passwords.md).
- Going to production (Redis-backed sessions so the device list is shared across workers): [Going to production](going-to-production.md).

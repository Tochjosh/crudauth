# Passwords

How CRUDAuth stores passwords, lets an OAuth-only user set one, and resets a forgotten one.

Storage and `POST /set-password` come with the base app; the reset flow additionally needs
email configured:

```python
auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    email=EmailConfig(sender=MySender(), frontend_url="https://app.example.com"),  # for reset
)
app.include_router(auth.router)   # adds /set-password and /password/reset-*
```

See [Getting started](../../getting-started.md) for the base app and [Email flows](email.md)
for the sender.

## Storage

Passwords are hashed with bcrypt, after a SHA-256 pre-hash so bcrypt's 72-byte ceiling never
silently truncates a long password. Verification returns `False` for a missing, malformed or
unusable stored hash instead of raising, so a corrupted row is a clean "invalid password", not a
500, and it still pays a full bcrypt verification, so an OAuth-only account answers a login in
the same time as one with a password. You never handle the plaintext beyond the route that
receives it.

Every password is Unicode-normalized (NFKC) before it's hashed or verified, as NIST SP 800-63B
recommends. An `é` typed as one precomposed character on one device and as `e` plus a combining
accent on another is the same password. Hashes created before normalization keep verifying: the
password is checked as typed when its normalized form doesn't match, and a successful login
replaces that hash with a normalized one.

bcrypt is deliberately slow, so the built-in routes hash and verify in a worker thread and the
event loop keeps serving other requests meanwhile. In your own async routes, use the async
counterparts:

```python
from crudauth import get_password_hash_async, verify_password_async

if not await verify_password_async(body.current_password, auth.repo.get(user, "hashed_password")):
    raise UnauthorizedException("Incorrect password")
await auth.repo.update(
    db, user, {"hashed_password": await get_password_hash_async(body.new_password)}
)
```

`get_password_hash` and `verify_password` do the same work synchronously, for scripts and sync
code. `crudauth.utils.verify_and_update_password_async` also returns the replacement hash for a
pre-normalization match, for a login you verify yourself instead of through
`auth.authenticate_password`.

## Password policy

Every new password, on `/register`, `/set-password`, `/change-password` and
`/password/reset-confirm`, must meet the configured `PasswordPolicy`. The default only requires
8 characters:

```python
from crudauth import CRUDAuth, PasswordPolicy

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    password_policy=PasswordPolicy(min_length=12, require_digit=True),
)
```

`require_uppercase`, `require_lowercase`, `require_digit` and `require_special` are off by
default. A special character is anything that isn't a letter or a digit, spaces included. There's
no maximum length: the SHA-256 pre-hash makes a long password as cheap to hash as a short one.
The rules and validators see the normalized password, the form that gets hashed, so `e` plus a
combining accent counts as one character and `²` counts as the digit `2`.

A password that fails gets a `422` in FastAPI's validation-error format, one entry per unmet
rule at the password field (`password` on `/register`, `new_password` everywhere else):

```json
{"detail": [
  {"type": "string_too_short", "loc": ["body", "new_password"],
   "msg": "String should have at least 12 characters", "ctx": {"min_length": 12}},
  {"type": "password_policy", "loc": ["body", "new_password"],
   "msg": "Password should contain a digit", "ctx": {"requirement": "digit"}}
]}
```

The rejected password isn't echoed back, and OpenAPI shows the minimum length and the rules on
each password field.

### Extra checks

For anything beyond the built-in rules, add `validators`: sync or async functions that raise
`ValueError` with the message to show. They run in order once the built-in rules pass and stop at
the first failure, so a breached-password lookup never runs for a password that's too short:

```python
from crudauth import CRUDAuth, PasswordContext, PasswordPolicy

async def not_breached(password: str) -> None:
    if await breach_count(password):
        raise ValueError("This password has appeared in a data breach")

def not_personal(password: str, context: PasswordContext) -> None:
    lowered = password.lower()
    for value in (context.username, context.email and context.email.split("@")[0]):
        if value and value.lower() in lowered:
            raise ValueError("Password should not contain your username or email")

auth = CRUDAuth(
    ...,
    password_policy=PasswordPolicy(min_length=12, validators=[not_breached, not_personal]),
)
```

A validator that takes a second required argument also gets a `PasswordContext`: the `source`
(`"register"`, `"set"`, `"change"` or `"reset"`), the account's `username` and `email`, and the
`user` row (`None` on registration). One with an optional second parameter gets only the
password.

### What the policy covers

The policy runs in CRUDAuth's routes, on a custom `register_schema` too, and in
`EmailFlowService.reset_password` when you call it directly. Code that sets a password itself
with `get_password_hash_async` should check it first:

```python
await auth.validate_password(new_password, user=user, source="change", field="new_password")
```

Tightening the policy doesn't affect existing passwords. Login never checks it, so users keep
signing in and meet the new rules the next time they set a password.

## Setting a password on an OAuth-only account

A user who signed up through OAuth has no usable password (the stored value is an unusable
sentinel). `POST /set-password` is a built-in route that lets them set their first one while
authenticated. The active session is the re-authentication, since there's no current password
to check.

```bash
# 1. set the password (the OAuth session cookie + CSRF header authenticate the call)
curl -X POST http://localhost:8000/set-password \
  -H "X-CSRF-Token: <token>" -H "Content-Type: application/json" \
  -b "session_id=<cookie>" \
  -d '{"new_password": "a-strong-one"}'

# 2. the account can now log in by password too
curl -X POST http://localhost:8000/login \
  -d "username=alice&password=a-strong-one"
```

This is **set**, not change: it refuses with `400` if the account already has a usable
password (use the reset flow to change an existing one), and it doesn't evict other sessions,
because establishing a first credential isn't a compromise response.

## Changing a known password

A signed-in user with a password changes it through `POST /change-password`, a built-in route. The
current password is the re-authentication (the active session/token proves presence, the current
password proves intent), so no token round-trip is needed.

```bash
curl -X POST http://localhost:8000/change-password \
  -H "X-CSRF-Token: <token>" -H "Content-Type: application/json" \
  -b "session_id=<cookie>" \
  -d '{"current_password": "old-one", "new_password": "a-new-strong-one"}'
```

Allowed over any transport: CSRF is automatic on the session path, and bearer has no CSRF surface.
A wrong current password is a `401`; an account with no usable password is a `400` (use
`/set-password` instead). Because a password change is a compromise response, it bumps
`token_version` (evicting bearer tokens) and revokes the user's *other* sessions, keeping the
current one, and fires the `on_after_password_changed` hook.

## Resetting a forgotten password

A user who can't log in uses the email reset flow: `POST /password/reset-request` sends a
link, and `POST /password/reset-confirm` sets the new password. See [Email flows](email.md)
for the setup. The reset also bumps `token_version`, so any bearer tokens issued before the
reset stop working.

---

[Next: Devices & sessions →](session-management.md){ .md-button .md-button--primary }

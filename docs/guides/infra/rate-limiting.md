# Rate limiting & lockout

Two related protections: a general-purpose per-endpoint rate limiter you attach to any route,
and an escalating login lockout that's built into the auth flows. Both run over the same
[rate-limiter backend](storage.md) (in-memory by default, Redis in production).

## Throttling a route

`auth.rate_limit(action, limit, key=...)` builds a dependency you add to any endpoint:

```python
from fastapi import Depends
from crudauth.ratelimit import RateLimit, KeyBy

@app.post("/contact", dependencies=[Depends(auth.rate_limit("contact", RateLimit(5, 60)))])
async def contact(...):
    ...
```

`RateLimit(times, seconds)` is the budget (5 per 60s above). It writes `X-RateLimit-*`
headers and raises a `RateLimitException` (`429` with `Retry-After`) when the caller is over
budget. `key` decides who shares a budget:

- `KeyBy.IP` (the default): the client IP.
- `KeyBy.USER`: the authenticated user. Unauthenticated requests get `401`.
- `KeyBy.USER_OR_IP`: the user when the request is authenticated, otherwise the client IP.
- A function of the request, `key(request)`, or of the request and the principal (`None` when
  anonymous), `key(request, principal)`. The principal is passed only when the function takes
  two required positional arguments.

The limit can depend on the request as well. Pass a function instead of a `RateLimit`: it
receives the request and the principal, may be sync or async, and returns a `RateLimit`, or
`None` for no limit on that request:

```python
async def plan_limit(request: Request, principal: Principal | None) -> RateLimit | None:
    if principal is None:
        return RateLimit(20, 60)
    if principal.is_superuser:
        return None
    return RateLimit(200, 60)

@app.get("/search", dependencies=[Depends(auth.rate_limit("search", plan_limit, key=KeyBy.USER_OR_IP))])
async def search(...):
    ...
```

The principal comes from the same cached authentication `current_user()` uses, so a route
with both authenticates once, and `current_user()` still enforces CSRF. `transport=` narrows
which credentials identify the caller, as it does on `current_user()`; give both the same
value so they keep sharing that authentication. Like `current_user(optional=True)`, a limit
that reads the principal treats a missing or expired credential as anonymous but rejects a
tampered one with `401`.

A limit that doesn't need the principal (a fixed `RateLimit` keyed by IP or by
`key(request)`) doesn't touch the database. For your own throttling logic,
`auth.rate_limiter` is the configured backend.

### Headers on error responses

`X-RateLimit-Limit` and `X-RateLimit-Remaining` go on the route's response, and the `429` carries
them with `Retry-After`. A request can also be counted and then refused by something after the
limiter: `current_user()` answering `401`, the route raising a `404`, a `422` for a bad body.
FastAPI builds those responses from the exception, so they leave without the headers, and a
client reading the headers to pace itself can't see that the refused requests spent budget.

Add `RateLimitHeadersMiddleware` to put the headers on those responses too:

```python
from crudauth.ratelimit import RateLimitHeadersMiddleware

app.add_middleware(RateLimitHeadersMiddleware)
```

It only fills in headers a response doesn't already have, and a request no limiter counted gets
none. When several limiters count the same request, the headers describe the one with the least
remaining, since that's the budget the client runs into first. Responses built outside the
middleware stack, such as an unhandled exception's `500`, go out without them.

The built-in account actions ship with defaults. Override them per action with `rate_limits={...}`
on `CRUDAuth`:

```python
auth = CRUDAuth(..., rate_limits={"register": RateLimit(3, 600)})  # 3 signups / 10 min per IP
```

An unknown key raises at construction, so these are the ones to pass:

| Action | Default | Guards |
|---|---|---|
| `register` | 5 / hour | `POST /register` |
| `email_verify_request` | 5 / hour | `POST /email/verify-request` |
| `password_reset_request` | 5 / hour | `POST /password/reset-request` |
| `email_change_request` | 3 / hour | `POST /email/change-request` |
| `existing_account_notice` | 5 / hour | the "you already have an account" notice |
| `change_password` | 5 / hour | `POST /change-password` and `POST /set-password` |
| `logout_all` | 10 / hour | `POST /logout-all` |
| `csrf_refresh` | 30 / hour | `POST /csrf/refresh` |
| `oauth_authorize` | 30 / hour | `GET /oauth/{provider}/authorize` |
| `mfa_manage` | 10 / hour | the MFA setup, confirm, disable and recovery-code routes |

`auth.rate_limits` reads the merged result back, defaults included.

`register` counts only signups that pass validation, so a rejected password doesn't use up the
budget.

A key that isn't a built-in action raises at construction; a custom action passes its limit to
`auth.rate_limit(action, RateLimit(...))`. `RateLimit` rejects a negative `times` or a
`seconds` that isn't positive.

`KeyBy.IP` keys an IPv6 client by its `/64`, the block one subscriber is normally given, so
rotating through addresses in it doesn't buy fresh budgets. The `register` limit and the login
lockout key IPs the same way. See [`client_ip_key`](../../api/utils.md).

## Login lockout

<p align="center">
  <img src="../../assets/diagrams/lockout-light.png#only-light" alt="After 5 failed attempts per IP and username, the first lockout is 60s, the next 120s, the next 240s, doubling each round up to a maximum; a successful login clears the counters" width="100%">
  <img src="../../assets/diagrams/lockout-dark.png#only-dark" alt="After 5 failed attempts per IP and username, the first lockout is 60s, the next 120s, the next 240s, doubling each round up to a maximum; a successful login clears the counters" width="100%">
</p>

The login path (the session `/login` and the bearer `/token`, which share it) has its own
escalating lockout, separate from `rate_limit()`. Repeated failures from an IP + username
trip a block whose duration doubles each round, up to a cap. Configure it on `CRUDAuth`, which
works whichever transports you use:

```python
from crudauth.ratelimit import LockoutConfig

auth = CRUDAuth(
    ...,
    lockout=LockoutConfig(
        max_attempts=5,               # failures allowed in the window
        attempt_window_seconds=60,
        lockout_base_seconds=60,      # first lockout; doubles each round
        lockout_max_seconds=3600,     # cap
        round_retention_seconds=3600, # how long the round count survives
        on_login_success="clear_all",
    ),
)
```

`SessionTransport`'s `login_max_attempts`, `login_attempt_window_seconds`,
`login_lockout_base_seconds`, `login_lockout_max_seconds` and `on_login_success` set the same
values; setting them and `lockout=` together raises.

- **Escalation:** each repeat offense waits longer (60s, 120s, 240s, ... up to the cap), and
  the round count persists so a slow, paced attack keeps climbing rather than resetting.
- **`on_login_success`:** a good login always clears that username's counters. `"clear_all"`
  (default) also takes back the per-IP failures that username added from that IP, which is
  friendly to users behind shared egress who mistyped before getting in. Failures against other
  usernames stay counted, so logging into your own account doesn't reset a spray, and an IP
  lock stays until it expires. `"clear_user_only"` keeps all per-IP pressure, which is tighter
  but only safe when your per-IP key identifies one client.
- **Usernames are case-folded** in the lockout key, so `bob`, `Bob` and `BOB` share one budget
  even when your database compares them case-insensitively.
- **Keying behind a proxy:** per-IP counters use the client IP, so set `trusted_proxy_hops` to
  the number of proxies in front of you. Otherwise every request looks like the proxy's IP and
  shares one bucket. Repeated `X-Forwarded-For` header lines are read as one chain. See
  [`get_client_ip`](../../api/utils.md).

Lockout **fails closed**: if the limiter backend errors, a login is blocked rather than
allowed, so an attacker can't disable it by knocking the backend over.

---

[Next: Hooks →](hooks.md){ .md-button .md-button--primary }

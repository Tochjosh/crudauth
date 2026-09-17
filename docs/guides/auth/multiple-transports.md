# Multiple transports

A web app and an API often live in the same backend. The browser wants a cookie session;
the API wants a bearer token. With CRUDAuth you enable both transports and your routes don't
change, because every transport resolves to the same Principal.

```python
from crudauth import CRUDAuth, SessionTransport, BearerTransport

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[
        SessionTransport(),   # browsers: cookies + CSRF
        BearerTransport(),    # API / mobile / CLI: JWT
    ],
)
```

<p align="center">
  <img src="../../assets/diagrams/identity-light.png#only-light" alt="Session cookies and bearer tokens both resolve through CRUDAuth into one Principal that the route gates on, regardless of transport" width="100%">
  <img src="../../assets/diagrams/identity-dark.png#only-dark" alt="Session cookies and bearer tokens both resolve through CRUDAuth into one Principal that the route gates on, regardless of transport" width="100%">
</p>

## First credential wins

Transports are tried in the order you list them, and the first credential that's *present*
wins. A transport returns nothing when its credential is absent (so the next one is tried),
but it raises for a credential that's present but invalid (for example a session cookie that
fails its CSRF check). That hard failure propagates even under `optional=True`, because a
tampered credential is an attack signal, not "anonymous".

Order by precedence. If a request could carry both a cookie and a token, list the one you
want to win first.

## Narrowing a route to one transport

Some endpoints should only accept one kind of credential. Pass `transport=` to restrict it:

```python
@app.post("/api/jobs")
async def create_job(user: Principal = Depends(auth.current_user(transport="bearer"))):
    ...   # rejects a cookie session even if one is present

@app.get("/account")
async def account(user: Principal = Depends(auth.current_user(transport="session"))):
    ...   # browser-only
```

You can also pass a list, `transport=["session", "bearer"]`, to accept a subset.

## CSRF stays where sessions are

CSRF is a property of the session transport. It's enforced on cookie-authenticated mutations
and is irrelevant to bearer requests, which don't ride a cookie. The first transport whose
credential is present authenticates the request, so a request that carries both a session cookie
and a bearer token is a session request when `SessionTransport` comes first, and its mutations
need the `X-CSRF-Token` header. A client that only sends the bearer token (a mobile app, a
server, a frontend that doesn't send cookies to the API) never deals with CSRF. To have a
request with both credentials authenticate by its token, list `BearerTransport` first or narrow
the route with `current_user(transport="bearer")`.

---

[Next: OAuth →](oauth.md){ .md-button .md-button--primary }

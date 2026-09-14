# Storage & lifespan

CRUDAuth keeps server-side state in a pluggable store: sessions, CSRF tokens, login-lockout
counters, and single-use email and OAuth tokens. In-memory is the zero-config default and
fine for development; Redis is what you want in production.

<p align="center">
  <img src="../../assets/diagrams/backends-light.png#only-light" alt="In-memory state lives in the process and is not shared across workers; Redis holds the same state shared across all workers and across restarts; the API is identical either way" width="100%">
  <img src="../../assets/diagrams/backends-dark.png#only-dark" alt="In-memory state lives in the process and is not shared across workers; Redis holds the same state shared across all workers and across restarts; the API is identical either way" width="100%">
</p>

## In-memory (default)

Nothing to configure. The catch: state lives in the process, so under multiple workers
(`uvicorn --workers 4`, gunicorn, several pods) it isn't shared. That silently weakens
lockout counters, sessions, and one-time-token atomicity. CRUDAuth logs a startup warning
whenever an in-memory backend is active. Use it for development, tests, and single-worker
deployments.

## Redis (production)

Pass a Redis URL to `CRUDAuth` and every store moves to Redis: sessions and CSRF tokens, the
lockout and throttle counters, and the one-time-token and OAuth-state stores. CRUDAuth opens one
client for the URL, shares it across all of them, and closes it in `auth.shutdown()`.

```python
from crudauth import CRUDAuth

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    redis_url="redis://localhost:6379/0",
)
```

Give auth state a Redis database of its own rather than sharing your cache's. A cache flush or an
eviction policy would otherwise log users out and reset lockout counters. Redis Cluster only has
database 0, so there it means a cluster of its own.

### Sharing a client

If your app already builds a Redis client (a tuned connection pool, TLS, Sentinel, or a
`RedisCluster`), pass it with `redis_client=` instead of a URL. CRUDAuth uses it for every store and never closes it:
`auth.shutdown()` only closes the clients CRUDAuth built from a URL, so the client's lifecycle stays
with your app. Either `decode_responses` setting works.

```python
from redis.asyncio import Redis

auth_redis = Redis.from_url(os.environ["AUTH_REDIS_URL"], max_connections=50)
auth = CRUDAuth(..., redis_client=auth_redis)
```

`redis_url` and `redis_client` are mutually exclusive.

### Overriding one part

The `CRUDAuth` setting is the default. Configure a part directly to put it somewhere else:

```python
from crudauth import CRUDAuth, SessionTransport
from crudauth.ratelimit import redis_rate_limiter

auth = CRUDAuth(
    ...,
    redis_client=auth_redis,
    transports=[SessionTransport(redis_client=session_redis)],  # sessions and CSRF tokens
    rate_limiter=redis_rate_limiter(client=limiter_redis),      # lockout and throttle counters
)
```

`SessionTransport(backend="memory")` keeps sessions in memory even when `CRUDAuth` has Redis.
The startup warning names each part that's still in memory; once you've deliberately accepted
that on a single worker, pass `warn_on_memory_backend=False` to silence it.

## Lifespan

Server-side backends open connections on startup, so call `initialize()` and `shutdown()`
from your app's lifespan. It's required for Redis and a no-op for in-memory.

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    await auth.initialize()
    yield
    await auth.shutdown()

app = FastAPI(lifespan=lifespan)
```

---

[Next: Rate limiting & lockout →](rate-limiting.md){ .md-button .md-button--primary }

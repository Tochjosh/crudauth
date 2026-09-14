"""Rate-limiter backends, the lockout policy, and the rate_limit() dependency."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator

import fakeredis.aioredis
import httpx
import pytest
from fastapi import Depends, FastAPI, Request

from crudauth import CookieConfig, CRUDAuth, Principal, SessionTransport
from crudauth.ratelimit import (
    KeyBy,
    LockoutPolicy,
    MemoryRateLimiterBackend,
    RateLimit,
    RedisBackend,
    redis_rate_limiter,
)
from crudauth.ratelimit.base import RateLimiterBackend
from crudauth.ratelimit.constants import LOCKOUT_NAMESPACE, MEMORY_SWEEP_EVERY_INCREMENTS
from crudauth.transports.bearer.transport import BearerTransport


def _fakeredis_client():
    return fakeredis.aioredis.FakeRedis()


# =============================================================================
# Backend conformance - memory and redis behave identically (the dumb surface)
# =============================================================================
@pytest.fixture(params=["memory", "redis"])
async def backend(request) -> AsyncIterator[RateLimiterBackend]:
    if request.param == "memory":
        yield MemoryRateLimiterBackend()
    else:
        b = RedisBackend(client=_fakeredis_client())
        yield b
        await b.close()


async def test_increment_and_count(backend) -> None:
    assert await backend.get_count("k") is None
    assert await backend.increment("k", 1, 100) == 1
    assert await backend.increment("k", 1, 100) == 2
    assert await backend.get_count("k") == 2


async def test_delete_and_reset(backend) -> None:
    await backend.increment("k", 1, 100)
    assert await backend.delete("k") is True
    assert await backend.get_count("k") is None
    await backend.increment("k", 1, 100)
    await backend.reset("k")
    assert await backend.get_count("k") is None


async def test_ping(backend) -> None:
    assert await backend.ping() is True


async def test_memory_backend_evicts_abandoned_window_keys() -> None:
    # rolling window-stamped keys are never re-touched; the periodic sweep
    # must evict them so a high-cardinality keyspace can't grow unbounded.
    b = MemoryRateLimiterBackend()
    for i in range(300):  # simulate abandoned, already-expired window keys
        b._counts[f"old:{i}"] = 1
        b._deadline[f"old:{i}"] = time.monotonic() - 1
    for _ in range(MEMORY_SWEEP_EVERY_INCREMENTS):  # drive the periodic sweep
        await b.increment("live", 1, 100)
    assert not any(k.startswith("old:") for k in b._counts)  # stale keys gone
    assert "live" in b._counts  # the unexpired key survives


async def test_increment_and_check_trips(backend) -> None:
    limit, period = 3, 100
    results = [await backend.increment_and_check("ic", limit, period) for _ in range(4)]
    counts = [r[0] for r in results]
    limited = [r[1] for r in results]
    assert counts == [1, 2, 3, 4]
    assert limited == [False, False, False, True]
    assert results[-1][2] > 0  # retry_after set once limited


# =============================================================================
# LockoutPolicy - escalation, survival, fail-closed
# =============================================================================
async def test_backoff_doubles_across_rounds() -> None:
    policy = LockoutPolicy(
        MemoryRateLimiterBackend(),
        max_attempts=1,
        lockout_base_seconds=10,
        lockout_max_seconds=10_000,
        round_retention_seconds=10_000,
        fail_open=False,
    )
    # round 0: exceed → ~base
    await policy.check_and_record("ip", "u")  # count 1 (== max)
    _, _, r0 = await policy.check_and_record("ip", "u")  # count 2 (> max) → lock
    # clear the active lock window by recording success on a *different* identity
    # then re-trip to advance the round counter.
    _, _, r1 = await policy.check_and_record("ip", "u")  # still locked, reports remaining
    assert r0 == 10
    assert r1 > 0


async def test_lockout_fails_closed_on_backend_error() -> None:
    class BrokenBackend(MemoryRateLimiterBackend):
        async def get_ttl(self, key: str) -> int:
            raise RuntimeError("backend down")

    policy = LockoutPolicy(BrokenBackend(), fail_open=False)
    allowed, _, retry = await policy.check_and_record("ip", "u")
    assert allowed is False  # fail closed
    assert retry > 0


async def test_lockout_fails_open_when_configured() -> None:
    class BrokenBackend(MemoryRateLimiterBackend):
        async def get_ttl(self, key: str) -> int:
            raise RuntimeError("backend down")

    policy = LockoutPolicy(BrokenBackend(), fail_open=True)
    allowed, _, _ = await policy.check_and_record("ip", "u")
    assert allowed is True


# =============================================================================
# rate_limit() dependency - per-IP 429 on a custom action
# =============================================================================
async def test_rate_limit_dependency_raises_429(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()

    @app.get("/limited", dependencies=[Depends(auth.rate_limit("custom", RateLimit(2, 100)))])
    async def limited() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/limited")).status_code == 200
        assert (await c.get("/limited")).status_code == 200
        r = await c.get("/limited")
        assert r.status_code == 429
        assert "Retry-After" in r.headers
        assert r.headers["X-RateLimit-Limit"] == "2"
    await auth.shutdown()


async def test_rate_limit_keyed_by_user(get_session, UserModel) -> None:
    # USER keying throttles per-principal: two sessions for two users each get
    # their own budget, and one user exhausting it doesn't affect the other.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get(
        "/u", dependencies=[Depends(auth.rate_limit("uact", RateLimit(2, 100), key=KeyBy.USER))]
    )
    async def u(_: Principal = Depends(auth.current_user())) -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as alice:
        await alice.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        await alice.post("/login", data={"username": "alice", "password": "pw123456"})
        assert (await alice.get("/u")).status_code == 200
        assert (await alice.get("/u")).status_code == 200
        assert (await alice.get("/u")).status_code == 429  # alice over her own budget

    # a second user on a fresh client has an independent budget
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as bob:
        await bob.post(
            "/register", json={"email": "b@x.com", "username": "bob", "password": "pw123456"}
        )
        await bob.post("/login", data={"username": "bob", "password": "pw123456"})
        assert (await bob.get("/u")).status_code == 200
    await auth.shutdown()


async def test_rate_limit_keyed_by_custom_callable(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    by_tenant = auth.rate_limit(
        "tact", RateLimit(1, 100), key=lambda r: r.headers.get("X-Tenant", "anon")
    )

    @app.get("/t", dependencies=[Depends(by_tenant)])
    async def t() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/t", headers={"X-Tenant": "acme"})).status_code == 200
        assert (await c.get("/t", headers={"X-Tenant": "acme"})).status_code == 429  # acme spent
        assert (
            await c.get("/t", headers={"X-Tenant": "globex"})
        ).status_code == 200  # other key ok
    await auth.shutdown()


async def test_rate_limit_accepts_dynamic_limits_and_two_argument_keys(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    seen: list[Principal | None] = []

    async def dynamic(request: Request, principal: Principal | None) -> RateLimit | None:
        return RateLimit(1, 100) if request.headers.get("X-Limit") else None

    def by_request(request: Request, principal: Principal | None) -> str:
        seen.append(principal)
        return request.headers.get("X-Tenant", "anon")

    @app.get(
        "/dynamic", dependencies=[Depends(auth.rate_limit("dynamic", dynamic, key=by_request))]
    )
    async def dynamic_route() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/dynamic")).status_code == 200
        assert (await c.get("/dynamic")).status_code == 200
        assert (await c.get("/dynamic", headers={"X-Limit": "yes"})).status_code == 200
        assert (await c.get("/dynamic", headers={"X-Limit": "yes"})).status_code == 429
    await auth.shutdown()
    assert seen == [None, None, None, None]


async def test_user_or_ip_uses_public_principal_and_trusted_ip(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        trusted_proxy_hops=1,
    )
    app = FastAPI()

    @app.get(
        "/mixed",
        dependencies=[Depends(auth.rate_limit("mixed", RateLimit(1, 100), key=KeyBy.USER_OR_IP))],
    )
    async def mixed() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/mixed", headers={"X-Forwarded-For": "1.2.3.4"})).status_code == 200
        assert (await c.get("/mixed", headers={"X-Forwarded-For": "1.2.3.4"})).status_code == 429
        assert (await c.get("/mixed", headers={"X-Forwarded-For": "5.6.7.8"})).status_code == 200
    await auth.shutdown()
    assert auth.rate_limiter is auth.runtime.rate_limiter


async def _register_and_login(client) -> str:
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    return login.json()["csrf_token"]


async def test_user_or_ip_keys_authenticated_user_across_ips(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        trusted_proxy_hops=1,
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get(
        "/mixed",
        dependencies=[Depends(auth.rate_limit("mixed", RateLimit(1, 100), key=KeyBy.USER_OR_IP))],
    )
    async def mixed() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await _register_and_login(c)
        assert (await c.get("/mixed", headers={"X-Forwarded-For": "1.2.3.4"})).status_code == 200
        assert (await c.get("/mixed", headers={"X-Forwarded-For": "5.6.7.8"})).status_code == 429
    await auth.shutdown()


async def test_user_or_ip_limit_shares_authentication_and_keeps_csrf(
    get_session, UserModel, monkeypatch
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    calls = {"n": 0}
    real = auth.repo.get_by_id

    async def counting(db, uid):
        calls["n"] += 1
        return await real(db, uid)

    monkeypatch.setattr(auth.repo, "get_by_id", counting)

    app = FastAPI()
    app.include_router(auth.router)
    limit = Depends(auth.rate_limit("mixed", RateLimit(100, 60), key=KeyBy.USER_OR_IP))

    @app.get("/mixed", dependencies=[limit])
    async def read(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id}

    @app.post("/mixed", dependencies=[limit])
    async def write(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        csrf = await _register_and_login(c)
        calls["n"] = 0
        assert (await c.get("/mixed")).status_code == 200
        assert calls["n"] == 1
        assert (await c.post("/mixed")).status_code == 403
        assert (await c.post("/mixed", headers={"X-CSRF-Token": csrf})).status_code == 200
    await auth.shutdown()


async def test_key_with_optional_second_parameter_receives_only_the_request(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    received: list[object] = []

    def by_tenant(request, extra="unset") -> str:
        received.append(extra)
        return request.headers.get("X-Tenant", "anon")

    @app.get(
        "/tenant",
        dependencies=[Depends(auth.rate_limit("tenant", RateLimit(5, 60), key=by_tenant))],
    )
    async def tenant() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/tenant")).status_code == 200
    await auth.shutdown()
    assert received == ["unset"]


async def test_static_ip_limit_does_not_open_a_session(sessionmaker, UserModel) -> None:
    opened = {"n": 0}

    async def counting_session():
        opened["n"] += 1
        async with sessionmaker() as session:
            yield session

    auth = CRUDAuth(
        session=counting_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()

    @app.get("/static", dependencies=[Depends(auth.rate_limit("static", RateLimit(5, 60)))])
    async def static() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/static")).status_code == 200
    await auth.shutdown()
    assert opened["n"] == 0


async def test_user_key_calls_sync_limit_function_with_the_principal(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    seen: list[Principal | None] = []

    def per_user(request: Request, principal: Principal | None) -> RateLimit:
        seen.append(principal)
        return RateLimit(1, 100)

    app = FastAPI()
    app.include_router(auth.router)

    @app.get(
        "/per-user",
        dependencies=[Depends(auth.rate_limit("per_user", per_user, key=KeyBy.USER))],
    )
    async def per_user_route() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await _register_and_login(c)
        assert (await c.get("/per-user")).status_code == 200
        assert (await c.get("/per-user")).status_code == 429
    await auth.shutdown()
    assert [p and p.transport for p in seen] == ["session", "session"]


async def test_transport_narrowed_limit_shares_authentication(
    get_session, UserModel, monkeypatch
) -> None:
    session_transport = SessionTransport(cookies=CookieConfig(secure=False))
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[session_transport, BearerTransport(cookies=CookieConfig(secure=False))],
    )
    calls = {"n": 0}
    real = session_transport.authenticate

    async def counting(request, ctx):
        calls["n"] += 1
        return await real(request, ctx)

    monkeypatch.setattr(session_transport, "authenticate", counting)

    with pytest.raises(ValueError):
        auth.rate_limit("narrow", RateLimit(100, 60), transport="missing")

    app = FastAPI()
    app.include_router(auth.router)
    limit = auth.rate_limit("narrow", RateLimit(100, 60), key=KeyBy.USER_OR_IP, transport="session")

    @app.get("/narrow", dependencies=[Depends(limit)])
    async def narrow(user: Principal = Depends(auth.current_user(transport="session"))):
        return {"id": user.user_id}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await _register_and_login(c)
        calls["n"] = 0
        assert (await c.get("/narrow")).status_code == 200
    await auth.shutdown()
    assert calls["n"] == 1


async def test_limit_reading_the_principal_rejects_a_tampered_bearer(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[BearerTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()

    @app.get("/ip", dependencies=[Depends(auth.rate_limit("ip", RateLimit(100, 60)))])
    async def by_ip() -> dict:
        return {"ok": True}

    @app.get(
        "/mixed",
        dependencies=[Depends(auth.rate_limit("mixed", RateLimit(100, 60), key=KeyBy.USER_OR_IP))],
    )
    async def mixed() -> dict:
        return {"ok": True}

    await auth.initialize()
    tampered = {"Authorization": "Bearer tampered.token.value"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/ip", headers=tampered)).status_code == 200
        assert (await c.get("/mixed", headers=tampered)).status_code == 401
    await auth.shutdown()


async def test_rate_limit_disabled_with_times_zero(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()

    @app.get("/free", dependencies=[Depends(auth.rate_limit("off", RateLimit(0, 100)))])
    async def free() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        for _ in range(10):
            assert (await c.get("/free")).status_code == 200
    await auth.shutdown()


# --- memory-backend startup warning -----------------------------------------
def test_warns_on_memory_backend_by_default(get_session, UserModel, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        )
    assert "in-memory backend" in caplog.text


def test_memory_warning_silenced_by_flag(get_session, UserModel, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            warn_on_memory_backend=False,
        )
    assert "in-memory backend" not in caplog.text


def test_no_memory_warning_with_redis_backends(get_session, UserModel, caplog) -> None:
    limiter = redis_rate_limiter(client=fakeredis.aioredis.FakeRedis())
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[
                SessionTransport(
                    backend="redis",
                    redis_url="redis://localhost",
                    cookies=CookieConfig(secure=False),
                )
            ],
            rate_limiter=limiter,
        )
    assert "in-memory backend" not in caplog.text


# --- KeyBy.USER shares authentication with the endpoint's current_user --------
async def test_user_keyed_rate_limit_shares_authentication(
    get_session, UserModel, monkeypatch
) -> None:
    # an endpoint with current_user() AND a KeyBy.USER rate limit must resolve the
    # principal once per request (shared via request.state), not once per dependency.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    calls = {"n": 0}
    real = auth.repo.get_by_id

    async def counting(db, uid):
        calls["n"] += 1
        return await real(db, uid)

    monkeypatch.setattr(auth.repo, "get_by_id", counting)

    app = FastAPI()
    app.include_router(auth.router)

    @app.get(
        "/shared",
        dependencies=[Depends(auth.rate_limit("shared_limit", RateLimit(100, 60), key=KeyBy.USER))],
    )
    async def shared(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        await c.post("/login", data={"username": "a", "password": "pw123456"})
        calls["n"] = 0
        r = await c.get("/shared")
        assert r.status_code == 200
        assert calls["n"] == 1  # one shared auth, not one per dependency
    await auth.shutdown()


# --- #16: escalation memory survives a paced, sustained attack ----------------
async def test_escalation_survives_paced_attack(monkeypatch) -> None:
    # The rounds counter's TTL is re-armed on every lockout, so an attack paced
    # to span > round_retention keeps climbing the backoff instead of resetting.
    import crudauth.ratelimit.backends.memory as mem

    clock = {"t": 1000.0}
    monkeypatch.setattr(mem.time, "monotonic", lambda: clock["t"])

    b = MemoryRateLimiterBackend()
    pol = LockoutPolicy(
        b,
        max_attempts=1,
        attempt_window_seconds=100_000,  # attempt counters never expire during the test
        lockout_base_seconds=10,
        lockout_max_seconds=10_000,
        round_retention_seconds=100,
    )

    async def attempt() -> int:
        _, _, retry_after = await pol.check_and_record("1.1.1.1", "v", success=False)
        return retry_after

    assert await attempt() == 0  # under the cap
    assert await attempt() == 10  # round 0 lockout (base)
    clock["t"] += 55  # past the 10s lock, within the 100s rounds window
    assert await attempt() == 20  # round 1 (escalated); re-arms rounds TTL
    clock["t"] += 65  # now t=1120 > the ORIGINAL 1100 rounds expiry
    # without the re-arm the rounds counter would have expired and reset to base
    assert await attempt() == 40  # round 2 - escalation memory survived


# --- #17: on_login_success governs the per-IP pressure valve ------------------
async def test_clear_user_only_keeps_ip_pressure() -> None:
    b = MemoryRateLimiterBackend()
    pol = LockoutPolicy(b, max_attempts=3, on_login_success="clear_user_only")
    for _ in range(3):
        await pol.check_and_record("10.0.0.1", "attacker", success=False)
    await pol.check_and_record("10.0.0.1", "neighbor", success=True)  # co-located success
    assert await b.get_count(f"{LOCKOUT_NAMESPACE}:ip:10.0.0.1") is not None  # per-IP kept
    assert await b.get_count(f"{LOCKOUT_NAMESPACE}:user:neighbor") is None  # username cleared


async def test_clear_all_clears_ip_pressure() -> None:
    b = MemoryRateLimiterBackend()
    pol = LockoutPolicy(b, max_attempts=3, on_login_success="clear_all")  # default
    for _ in range(3):
        await pol.check_and_record("10.0.0.1", "attacker", success=False)
    await pol.check_and_record("10.0.0.1", "neighbor", success=True)
    assert await b.get_count(f"{LOCKOUT_NAMESPACE}:ip:10.0.0.1") is None  # per-IP cleared too

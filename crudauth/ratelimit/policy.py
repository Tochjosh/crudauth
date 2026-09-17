"""Escalating login-lockout policy, built over the dumb backend primitives.

Relocated out of ``SessionManager`` into the kernel so it reads
``runtime.rate_limiter`` rather than a limiter the transport built. Per-IP and
per-username failure counters with exponential backoff and round retention.
"""

from __future__ import annotations

import logging

from ..constants import (
    DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
    DEFAULT_LOGIN_MAX_ATTEMPTS,
    DEFAULT_LOGIN_ROUND_RETENTION_SECONDS,
)
from ..utils import canonical_identifier, client_ip_key
from .base import RateLimiterBackend
from .config import LoginSuccessClears
from .constants import LOCKOUT_NAMESPACE

__all__ = ["LockoutPolicy"]

logger = logging.getLogger("crudauth.ratelimit")


class LockoutPolicy:
    """Tracks failed logins and escalates lockout duration across rounds.

    Fails **closed** by default: if the backend errors, a login attempt is
    blocked rather than silently allowed. Rationale: under fail-open an attacker
    who can DoS the limiter backend then brute-forces with lockout disabled.

    Note:
        Fail-closed means a network-backend outage blocks logins; pair a redis
        backend with HA redis (the in-memory backend has no outage mode).

    Args:
        backend: The shared rate-limiter backend (counters live here).
        max_attempts: Failures allowed within ``attempt_window_seconds`` before
            a lockout trips.
        attempt_window_seconds: Sliding window for counting failures.
        lockout_base_seconds: First lockout duration; doubles each round.
        lockout_max_seconds: Cap on the exponential lockout duration.
        round_retention_seconds: How long a round counter persists, so repeat
            offenders resume escalating rather than resetting. The TTL is slid
            forward on every lockout (sliding window), so a slow, paced attack
            keeps climbing the escalation ladder instead of forgetting it.
        on_login_success: What a successful login clears. Both modes clear the
            username's own counters, lock and rounds. ``"clear_all"`` (default)
            also takes back the per-IP pressure that this username's own failures
            from this IP added in the current attempt window - friendly to a
            legitimate user behind a shared egress (corporate NAT / mobile CGNAT)
            who mistyped before getting in, while failures against other
            usernames stay counted, so logging into your own account can't
            launder a spray. ``"clear_user_only"`` keeps all per-IP pressure -
            tighter against a single-source brute force, but only safe when your
            per-IP key reliably identifies an individual client (you terminate
            behind a proxy with ``trusted_proxy_hops`` set AND your users aren't
            predominantly behind shared egress); otherwise it can lock out
            innocent co-located users. A success never clears an IP lock or the
            IP's escalation rounds.
        fail_open: On a backend error, allow (``True``) or block (``False``).
    """

    def __init__(
        self,
        backend: RateLimiterBackend,
        *,
        max_attempts: int = DEFAULT_LOGIN_MAX_ATTEMPTS,
        attempt_window_seconds: int = DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
        lockout_base_seconds: int = DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
        lockout_max_seconds: int = DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
        round_retention_seconds: int = DEFAULT_LOGIN_ROUND_RETENTION_SECONDS,
        on_login_success: LoginSuccessClears = "clear_all",
        fail_open: bool = False,
    ):
        self.backend = backend
        self.max_attempts = max_attempts
        self.attempt_window = attempt_window_seconds
        self.lockout_base = lockout_base_seconds
        self.lockout_max = lockout_max_seconds
        self.round_retention = round_retention_seconds
        self.on_login_success = on_login_success
        self.fail_open = fail_open

    async def check_and_record(
        self, ip_address: str, username: str, success: bool = False
    ) -> tuple[bool, int | None, int]:
        """Record an attempt and report whether it's allowed.

        Args:
            ip_address: Caller IP (one of the two keyed dimensions). Keyed through
                [client_ip_key][crudauth.utils.client_ip_key], so an IPv6 client
                shares one budget across its ``/64``.
            username: Submitted username/email (the other dimension). Keyed through
                [canonical_identifier][crudauth.utils.canonical_identifier], so case
                variants share one budget.
            success: When ``True``, clears the username's counters (and, under
                ``"clear_all"``, the IP pressure its own failures added) and allows.

        Returns:
            ``(allowed, attempts_remaining, retry_after_seconds)``.

        Note:
            The escalation branch issues several sequential backend ops (per-IP
            and per-username lock + round counters). It runs only on *repeated
            failures* (already past the attempt cap), so it's intentionally not
            pipelined.
        """
        ns = LOCKOUT_NAMESPACE
        ip = client_ip_key(ip_address)
        user = canonical_identifier(username)
        ip_attempts = f"{ns}:ip:{ip}"
        user_attempts = f"{ns}:user:{user}"
        pair_attempts = f"{ns}:pair:{ip}:{user}"
        ip_lock = f"{ns}:lock:ip:{ip}"
        user_lock = f"{ns}:lock:user:{user}"
        ip_rounds = f"{ns}:rounds:ip:{ip}"
        user_rounds = f"{ns}:rounds:user:{user}"
        b = self.backend

        try:
            if success:
                for key in (user_attempts, user_lock, user_rounds):
                    await b.delete(key)
                if self.on_login_success == "clear_all":
                    own_failures = await b.get_count(pair_attempts)
                    if own_failures and await b.delete(pair_attempts):
                        await b.increment(ip_attempts, -own_failures, self.attempt_window)
                return True, None, 0

            active_lockout = max(await b.get_ttl(ip_lock), await b.get_ttl(user_lock))
            if active_lockout > 0:
                return False, 0, active_lockout

            ip_count = await b.increment(ip_attempts, 1, self.attempt_window)
            user_count = await b.increment(user_attempts, 1, self.attempt_window)
            if self.on_login_success == "clear_all":
                ip_window = await b.get_ttl(ip_attempts)
                if ip_window > 0:
                    await b.increment(pair_attempts, 1, ip_window)
            attempt_count = max(ip_count, user_count)
            remaining = max(0, self.max_attempts - attempt_count)
            if attempt_count <= self.max_attempts:
                return True, remaining, 0

            rounds = max((await b.get_count(ip_rounds)) or 0, (await b.get_count(user_rounds)) or 0)
            retry_after = min(self.lockout_base * (2**rounds), self.lockout_max)
            round_ttl = max(retry_after, self.round_retention)
            await b.increment(ip_lock, 1, retry_after)
            await b.increment(user_lock, 1, retry_after)
            await b.increment_and_refresh_ttl(ip_rounds, 1, round_ttl)
            await b.increment_and_refresh_ttl(user_rounds, 1, round_ttl)
            return False, 0, retry_after
        except Exception as exc:
            logger.warning("lockout backend error (fail_open=%s): %s", self.fail_open, exc)
            if self.fail_open:
                return True, None, 0
            return False, 0, self.lockout_base

    async def forget_attempt(self, ip_address: str, username: str) -> None:
        """Take back the one attempt a correct password recorded, leaving earlier failures.

        For a login that still needs a second factor: the password neither clears the
        counters nor uses up the budget the codes that follow are checked against.
        """
        ns = LOCKOUT_NAMESPACE
        ip = client_ip_key(ip_address)
        user = canonical_identifier(username)
        keys = [f"{ns}:ip:{ip}", f"{ns}:user:{user}"]
        if self.on_login_success == "clear_all":
            keys.append(f"{ns}:pair:{ip}:{user}")
        try:
            for key in keys:
                if (await self.backend.get_count(key) or 0) > 0:
                    await self.backend.increment(key, -1, self.attempt_window)
        except Exception as exc:
            logger.warning("lockout backend error while forgetting an attempt: %s", exc)

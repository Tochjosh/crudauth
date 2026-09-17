"""Rate-limit policy values and key strategy (code, not DB rows)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Literal, get_args

from fastapi import Request

from ..constants import (
    DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
    DEFAULT_LOGIN_MAX_ATTEMPTS,
    DEFAULT_LOGIN_ROUND_RETENTION_SECONDS,
    SECONDS_PER_HOUR,
)
from ..principal import Principal

__all__ = ["RateLimit", "RateLimitResolver", "KeyBy", "DEFAULT_RATE_LIMITS", "LockoutConfig"]

LoginSuccessClears = Literal["clear_all", "clear_user_only"]


@dataclass(frozen=True)
class RateLimit:
    """A fixed-window allowance: ``times`` events per ``seconds``.

    ``times=0`` disables the limit (an explicit, documented off switch, never the
    low-friction default).

    Raises:
        ValueError: If ``times`` is negative or ``seconds`` isn't positive.

    Example:
        ```python
        CRUDAuth(..., rate_limits={"password_reset_request": RateLimit(3, 1800)})
        ```
    """

    times: int
    seconds: int

    def __post_init__(self) -> None:
        if self.times < 0:
            raise ValueError(f"RateLimit times must be >= 0 (0 disables it), got {self.times}")
        if self.seconds <= 0:
            raise ValueError(f"RateLimit seconds must be > 0, got {self.seconds}")

    @property
    def disabled(self) -> bool:
        """True when ``times == 0`` (the limit is turned off)."""
        return self.times == 0


RateLimitResolver = Callable[
    [Request, Principal | None], RateLimit | None | Awaitable[RateLimit | None]
]
"""A per-request limit: a sync or async function of the request and the principal (``None``
when anonymous) returning a ``RateLimit``, or ``None`` for no limit on that request."""


class KeyBy(str, Enum):
    """Which dimension a [CRUDAuth.rate_limit][crudauth.crud_auth.CRUDAuth.rate_limit] dependency keys on."""

    IP = "ip"
    USER = "user"
    USER_OR_IP = "user_or_ip"


# Auth-adjacent endpoints protected out of the box. Apps tune via
# ``CRUDAuth(rate_limits={...})`` but can't ship them unprotected. Login is not
# here - it uses the escalating LockoutPolicy, configured with ``CRUDAuth(lockout=...)``.
DEFAULT_RATE_LIMITS: dict[str, RateLimit] = {
    "register": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "email_verify_request": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "password_reset_request": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "email_change_request": RateLimit(times=3, seconds=SECONDS_PER_HOUR),
    "existing_account_notice": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "change_password": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "logout_all": RateLimit(times=10, seconds=SECONDS_PER_HOUR),
    "csrf_refresh": RateLimit(times=30, seconds=SECONDS_PER_HOUR),
    "oauth_authorize": RateLimit(times=30, seconds=SECONDS_PER_HOUR),
}


@dataclass(frozen=True)
class LockoutConfig:
    """Tuning for the escalating login lockout shared by ``/login`` and ``/token``.

    Passed as ``CRUDAuth(lockout=...)``, so it applies whichever transports are
    configured. See [LockoutPolicy][crudauth.ratelimit.policy.LockoutPolicy] for
    how each value is used.

    Args:
        max_attempts: Failures allowed within ``attempt_window_seconds`` before a
            lockout trips.
        attempt_window_seconds: How long failures keep counting.
        lockout_base_seconds: First lockout duration; doubles each round.
        lockout_max_seconds: Cap on the exponential lockout duration.
        round_retention_seconds: How long the escalation round count survives
            without a new lockout.
        on_login_success: What a successful login clears, ``"clear_all"``
            (default) or ``"clear_user_only"``.

    Raises:
        ValueError: If ``max_attempts`` or a duration isn't positive, or
            ``on_login_success`` isn't one of the two modes.

    Example:
        ```python
        from crudauth.ratelimit import LockoutConfig

        CRUDAuth(..., lockout=LockoutConfig(max_attempts=10, lockout_max_seconds=900))
        ```
    """

    max_attempts: int = DEFAULT_LOGIN_MAX_ATTEMPTS
    attempt_window_seconds: int = DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS
    lockout_base_seconds: int = DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS
    lockout_max_seconds: int = DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS
    round_retention_seconds: int = DEFAULT_LOGIN_ROUND_RETENTION_SECONDS
    on_login_success: LoginSuccessClears = "clear_all"

    def __post_init__(self) -> None:
        positive = {
            "max_attempts": self.max_attempts,
            "attempt_window_seconds": self.attempt_window_seconds,
            "lockout_base_seconds": self.lockout_base_seconds,
            "lockout_max_seconds": self.lockout_max_seconds,
            "round_retention_seconds": self.round_retention_seconds,
        }
        for name, value in positive.items():
            if value <= 0:
                raise ValueError(f"LockoutConfig {name} must be > 0, got {value}")
        modes = get_args(LoginSuccessClears)
        if self.on_login_success not in modes:
            raise ValueError(
                f"LockoutConfig on_login_success must be one of {list(modes)}, "
                f"got {self.on_login_success!r}"
            )

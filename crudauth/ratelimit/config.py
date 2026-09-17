"""Rate-limit policy values and key strategy (code, not DB rows)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable

from fastapi import Request

from ..constants import SECONDS_PER_HOUR
from ..principal import Principal

__all__ = ["RateLimit", "RateLimitResolver", "KeyBy", "DEFAULT_RATE_LIMITS"]


@dataclass(frozen=True)
class RateLimit:
    """A fixed-window allowance: ``times`` events per ``seconds``.

    ``times=0`` disables the limit (an explicit, documented off switch, never the
    low-friction default).

    Example:
        ```python
        CRUDAuth(..., rate_limits={"password_reset_request": RateLimit(3, 1800)})
        ```
    """

    times: int
    seconds: int

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
# here - it uses the escalating LockoutPolicy, configured on SessionTransport.
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

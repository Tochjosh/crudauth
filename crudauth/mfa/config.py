"""Configuration for TOTP multi-factor authentication."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .constants import DEFAULT_CHALLENGE_TTL_SECONDS, DEFAULT_MAX_CODE_ATTEMPTS, RECOVERY_CODE_COUNT

__all__ = ["MfaConfig", "MfaRequirement"]

MfaRequirement = bool | Callable[[Any], bool | Awaitable[bool]]
"""``True``, ``False``, or a sync/async predicate over the user row."""


@dataclass(frozen=True)
class MfaConfig:
    """Opt-in TOTP (authenticator app) second factor, passed as ``CRUDAuth(mfa=...)``.

    Args:
        issuer: Name the authenticator app shows next to the account.
        encryption_key: Fernet key that encrypts TOTP secrets at rest, or a list of
            keys for rotation (the first encrypts, any decrypts). Must differ from
            ``SECRET_KEY``.
        required: Whether an account must use MFA: ``False`` (default), ``True``,
            or a sync/async predicate over the user row. A required account that
            isn't enrolled enrolls during login.
        oauth: Also challenge OAuth logins. Off by default, since the identity
            provider owns the second factor there.
        challenge_ttl_seconds: How long a login challenge can be answered.
        max_code_attempts: Wrong codes a challenge survives.
        recovery_code_count: Recovery codes issued at enrollment and on regeneration.

    Raises:
        ValueError: If ``issuer`` or ``encryption_key`` is empty, or a number isn't
            positive.

    Example:
        ```python
        auth = CRUDAuth(
            ...,
            mfa=MfaConfig(
                issuer="Acme",
                encryption_key=os.environ["MFA_ENCRYPTION_KEY"],
                required=lambda user: user.is_superuser,
            ),
        )
        ```
    """

    issuer: str
    encryption_key: str | bytes | Sequence[str | bytes]
    required: MfaRequirement = False
    oauth: bool = False
    challenge_ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS
    max_code_attempts: int = DEFAULT_MAX_CODE_ATTEMPTS
    recovery_code_count: int = RECOVERY_CODE_COUNT

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("MfaConfig issuer is required")
        if not self.encryption_keys:
            raise ValueError("MfaConfig encryption_key is required")
        for name in ("challenge_ttl_seconds", "max_code_attempts", "recovery_code_count"):
            if getattr(self, name) <= 0:
                raise ValueError(f"MfaConfig {name} must be > 0, got {getattr(self, name)}")

    @property
    def encryption_keys(self) -> list[str]:
        """``encryption_key`` as a list of strings, the encrypting key first."""
        keys = (
            [self.encryption_key]
            if isinstance(self.encryption_key, (str, bytes))
            else list(self.encryption_key)
        )
        return [key.decode() if isinstance(key, bytes) else key for key in keys if key]

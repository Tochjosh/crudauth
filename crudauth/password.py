"""Configurable password validation shared by password-writing paths."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Callable

from .constants import MIN_PASSWORD_LENGTH
from .exceptions import UnprocessableEntityException

PasswordValidator = Callable[[str], None]


@dataclass(frozen=True)
class PasswordPolicy:
    """Password requirements; composition checks are opt-in."""

    min_length: int = MIN_PASSWORD_LENGTH
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_special: bool = False

    def __call__(self, password: str) -> None:
        errors: list[str] = []
        if len(password) < self.min_length:
            errors.append(f"at least {self.min_length} characters")
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("an uppercase letter")
        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("a lowercase letter")
        if self.require_digit and not any(c.isdigit() for c in password):
            errors.append("a digit")
        if self.require_special and not any(not c.isalnum() for c in password):
            errors.append("a special character")
        if errors:
            raise ValueError("Password must contain " + ", ".join(errors) + ".")


async def validate_password(password: str, policy: PasswordValidator) -> None:
    """Apply a policy and expose failures as a 422 response.

    Supports both sync and async validators. Async validators are awaited.
    """
    try:
        result = policy(password)
        if inspect.isawaitable(result):
            await result
    except UnprocessableEntityException:
        raise
    except ValueError as exc:
        raise UnprocessableEntityException(str(exc) or "Password does not meet policy.") from exc


__all__ = ["PasswordPolicy", "PasswordValidator", "validate_password"]

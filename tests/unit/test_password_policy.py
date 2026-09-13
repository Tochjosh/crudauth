"""Shared password policy behavior."""

import pytest

from crudauth import PasswordPolicy
from crudauth.exceptions import UnprocessableEntityException
from crudauth.password import validate_password


async def test_policy_lists_all_failures() -> None:
    policy = PasswordPolicy(
        min_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_digit=True,
        require_special=True,
    )
    with pytest.raises(UnprocessableEntityException, match="12 characters.*uppercase.*digit"):
        await validate_password("short", policy)


async def test_callable_policy_is_supported() -> None:
    def policy(password: str) -> None:
        if "password" in password.lower():
            raise ValueError("must not contain password")

    with pytest.raises(UnprocessableEntityException, match="must not contain password"):
        await validate_password("password123", policy)


async def test_async_callable_policy_is_supported() -> None:
    async def breached(password: str) -> None:
        if password == "hunter2hunter2":
            raise ValueError("password is breached")

    await validate_password("safe-password", breached)
    with pytest.raises(UnprocessableEntityException, match="password is breached"):
        await validate_password("hunter2hunter2", breached)


async def test_validate_password_raises_on_value_error_not_type_error() -> None:
    """TypeError inside a validator should propagate, not be caught as a policy failure."""
    def bad_validator(password: str) -> None:
        raise TypeError("bug in validator")

    with pytest.raises(TypeError, match="bug in validator"):
        await validate_password("anything", bad_validator)

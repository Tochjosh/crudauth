"""Shared password policy behavior."""

import pytest

from crudauth import PasswordPolicy
from crudauth.exceptions import UnprocessableEntityException
from crudauth.password import validate_password


def test_policy_lists_all_failures() -> None:
    policy = PasswordPolicy(
        min_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_digit=True,
        require_special=True,
    )
    with pytest.raises(UnprocessableEntityException, match="12 characters.*uppercase.*digit"):
        validate_password("short", policy)


def test_callable_policy_is_supported() -> None:
    def policy(password: str) -> None:
        if "password" in password.lower():
            raise ValueError("must not contain password")

    with pytest.raises(UnprocessableEntityException, match="must not contain password"):
        validate_password("password123", policy)

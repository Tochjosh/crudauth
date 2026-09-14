"""PasswordPolicy rules, validators and the 422 they produce."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, field_validator

from crudauth import PasswordContext, PasswordPolicy, PasswordPolicyException

CONTEXT = PasswordContext(source="register", username="alice", email="alice@example.com")


async def test_built_in_rules_report_every_unmet_requirement() -> None:
    policy = PasswordPolicy(
        min_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_digit=True,
        require_special=True,
    )
    assert await policy.check("short", CONTEXT) == [
        {
            "type": "string_too_short",
            "msg": "String should have at least 12 characters",
            "ctx": {"min_length": 12},
        },
        {
            "type": "password_policy",
            "msg": "Password should contain an uppercase letter",
            "ctx": {"requirement": "uppercase"},
        },
        {
            "type": "password_policy",
            "msg": "Password should contain a digit",
            "ctx": {"requirement": "digit"},
        },
        {
            "type": "password_policy",
            "msg": "Password should contain a special character",
            "ctx": {"requirement": "special"},
        },
    ]
    assert await policy.check("Longer-pass1", CONTEXT) == []


async def test_enforce_raises_a_validation_shaped_422_at_the_field() -> None:
    with pytest.raises(PasswordPolicyException) as error:
        await PasswordPolicy(min_length=12).enforce("short", CONTEXT, field="new_password")
    assert error.value.status_code == 422
    assert error.value.detail == [
        {
            "type": "string_too_short",
            "loc": ["body", "new_password"],
            "msg": "String should have at least 12 characters",
            "ctx": {"min_length": 12},
        }
    ]


async def test_digit_rule_needs_a_decimal_digit() -> None:
    policy = PasswordPolicy(require_digit=True)
    assert await policy.check("password²²", CONTEXT) != []
    assert await policy.check("password22", CONTEXT) == []


async def test_validators_run_after_the_rules_pass_and_stop_at_the_first_failure() -> None:
    calls: list[str] = []

    def too_common(password: str) -> None:
        calls.append("too_common")
        if password == "correcthorse":
            raise ValueError("This password is too common")

    async def not_breached(password: str) -> None:
        calls.append("not_breached")

    policy = PasswordPolicy(min_length=10, validators=[too_common, not_breached])

    assert await policy.check("short", CONTEXT) != []
    assert calls == []
    assert await policy.check("correcthorse", CONTEXT) == [
        {"type": "password_policy", "msg": "This password is too common"}
    ]
    assert calls == ["too_common"]
    assert await policy.check("battery-staple", CONTEXT) == []
    assert calls == ["too_common", "too_common", "not_breached"]


async def test_validators_taking_two_arguments_receive_the_context() -> None:
    received: list[object] = []

    def optional_second(password: str, extra: object = "unset") -> None:
        received.append(extra)

    def not_personal(password: str, context: PasswordContext) -> None:
        received.append(context)
        if context.username and context.username in password:
            raise ValueError("Password should not contain your username")

    policy = PasswordPolicy(validators=[optional_second, not_personal])

    assert await policy.check("alice-password", CONTEXT) == [
        {"type": "password_policy", "msg": "Password should not contain your username"}
    ]
    assert received == ["unset", CONTEXT]


async def test_pydantic_validation_errors_keep_only_their_messages() -> None:
    class Phrase(BaseModel):
        value: str

        @field_validator("value")
        @classmethod
        def no_spaces(cls, value: str) -> str:
            if " " in value:
                raise ValueError("no spaces allowed")
            return value

    def as_phrase(password: str) -> None:
        Phrase(value=password)

    errors = await PasswordPolicy(validators=[as_phrase]).check("has a space", CONTEXT)

    assert errors == [{"type": "password_policy", "msg": "Value error, no spaces allowed"}]


async def test_errors_other_than_value_error_propagate() -> None:
    def broken(password: str) -> None:
        raise TypeError("bug in validator")

    with pytest.raises(TypeError, match="bug in validator"):
        await PasswordPolicy(validators=[broken]).check("long-enough", CONTEXT)


def test_min_length_must_be_at_least_one() -> None:
    with pytest.raises(ValueError):
        PasswordPolicy(min_length=0)


def test_description_lists_the_built_in_rules() -> None:
    assert PasswordPolicy().description == "At least 8 characters."
    assert (
        PasswordPolicy(min_length=1, require_digit=True).description
        == "At least 1 character, including a digit."
    )
    assert (
        PasswordPolicy(
            min_length=12, require_uppercase=True, require_digit=True, require_special=True
        ).description
        == "At least 12 characters, including an uppercase letter, a digit and a special character."
    )

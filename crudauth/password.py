"""[PasswordPolicy][crudauth.password.PasswordPolicy] - the rules every new password must meet."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from .constants import MIN_PASSWORD_LENGTH
from .exceptions import PasswordPolicyException
from .utils import takes_two_arguments

if TYPE_CHECKING:  # pragma: no cover
    from .repository import UserRepository

__all__ = ["PasswordContext", "PasswordPolicy", "PasswordSource", "PasswordValidator"]

PasswordSource = Literal["register", "set", "change", "reset"]
PasswordValidator = Callable[..., None | Awaitable[None]]

_REQUIREMENTS: tuple[tuple[str, str, Callable[[str], bool]], ...] = (
    ("uppercase", "an uppercase letter", str.isupper),
    ("lowercase", "a lowercase letter", str.islower),
    ("digit", "a digit", str.isdecimal),
    ("special", "a special character", lambda char: not char.isalnum()),
)


def _characters(count: int) -> str:
    return "character" if count == 1 else "characters"


@dataclass(frozen=True)
class PasswordContext:
    """Who a new password is for, passed to validators that take a second argument.

    Attributes:
        source: The flow setting the password: ``"register"``, ``"set"``, ``"change"``
            or ``"reset"``.
        username: The account's username, or ``None`` when the account shape has none.
        email: The account's email, or ``None`` when the account shape has none.
        user: The user row, or ``None`` on registration.
    """

    source: PasswordSource
    username: str | None = None
    email: str | None = None
    user: Any = None

    @classmethod
    def for_user(cls, repo: UserRepository, source: PasswordSource, user: Any) -> PasswordContext:
        """The context for an existing ``user``, with its username and email read through ``repo``."""
        return cls(
            source=source,
            username=repo.get(user, "username"),
            email=repo.get(user, "email"),
            user=user,
        )


@dataclass(frozen=True)
class PasswordPolicy:
    """The rules a new password must meet, on registration, set, change and reset.

    The built-in rules run first and every unmet one is reported. ``validators``
    run after them, in order, only once the built-in rules pass, and stop at the
    first that fails. A validator is a sync or async function that raises
    ``ValueError`` with the message to show. It's called with ``(password)``, or
    with ``(password, context)`` and a [PasswordContext][crudauth.password.PasswordContext]
    when it takes two required positional arguments.

    Attributes:
        min_length: The fewest characters allowed, at least 1.
        require_uppercase: Require an uppercase letter.
        require_lowercase: Require a lowercase letter.
        require_digit: Require a decimal digit.
        require_special: Require a character that isn't a letter or a digit, spaces included.
        validators: Extra checks, such as a breached-password lookup.

    Example:
        ```python
        async def not_breached(password: str) -> None:
            if await breach_count(password):
                raise ValueError("This password has appeared in a data breach")

        auth = CRUDAuth(..., password_policy=PasswordPolicy(min_length=12, validators=[not_breached]))
        ```
    """

    min_length: int = MIN_PASSWORD_LENGTH
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_special: bool = False
    validators: Sequence[PasswordValidator] = ()

    def __post_init__(self) -> None:
        if self.min_length < 1:
            raise ValueError("PasswordPolicy.min_length must be at least 1")
        object.__setattr__(self, "validators", tuple(self.validators))

    @property
    def description(self) -> str:
        """The built-in rules as a sentence, shown on password fields in OpenAPI."""
        required = [label for name, label, _ in _REQUIREMENTS if getattr(self, f"require_{name}")]
        if len(required) > 1:
            required = [", ".join(required[:-1]), required[-1]]
        text = f"At least {self.min_length} {_characters(self.min_length)}"
        if required:
            text += ", including " + " and ".join(required)
        return text + "."

    def body_field(self) -> Any:
        """The request-body type for a new password.

        It documents the policy in OpenAPI without validating in pydantic, so a
        rejected password is never echoed back in the error body; routes call
        [enforce][crudauth.password.PasswordPolicy.enforce] instead.
        """
        return Annotated[
            str,
            Field(description=self.description, json_schema_extra={"minLength": self.min_length}),
        ]

    async def check(self, password: str, context: PasswordContext) -> list[dict[str, Any]]:
        """Return one error per unmet built-in rule, or the first failing validator's error."""
        errors = self._rule_errors(password)
        if errors:
            return errors
        for validator in self.validators:
            try:
                if takes_two_arguments(validator):
                    result = validator(password, context)
                else:
                    result = validator(password)
                if inspect.isawaitable(result):
                    await result
            except ValueError as exc:
                return [
                    {
                        "type": "password_policy",
                        "msg": str(exc) or "Password doesn't meet the policy",
                    }
                ]
        return []

    async def enforce(
        self, password: str, context: PasswordContext, *, field: str = "password"
    ) -> None:
        """Raise [PasswordPolicyException][crudauth.exceptions.PasswordPolicyException] (422) when ``password`` fails."""
        errors = await self.check(password, context)
        if errors:
            raise PasswordPolicyException(field, errors)

    def _rule_errors(self, password: str) -> list[dict[str, Any]]:
        errors: list[dict[str, Any]] = []
        if len(password) < self.min_length:
            errors.append(
                {
                    "type": "string_too_short",
                    "msg": f"String should have at least {self.min_length} {_characters(self.min_length)}",
                    "ctx": {"min_length": self.min_length},
                }
            )
        for name, label, matches in _REQUIREMENTS:
            if getattr(self, f"require_{name}") and not any(matches(char) for char in password):
                errors.append(
                    {
                        "type": "password_policy",
                        "msg": f"Password should contain {label}",
                        "ctx": {"requirement": name},
                    }
                )
        return errors

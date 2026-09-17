"""HTTP exceptions raised by crudauth.

These mirror the FastCRUD exception hierarchy so apps already using FastCRUD
get consistent error shapes, but crudauth carries its own copies to stay
dependency-light.
"""

from http import HTTPStatus
from typing import Any

from fastapi import HTTPException, status

__all__ = [
    "CustomException",
    "BadRequestException",
    "OAuthAccountException",
    "NotFoundException",
    "ForbiddenException",
    "UnauthorizedException",
    "UnprocessableEntityException",
    "DuplicateValueException",
    "ValueTooLongException",
    "PasswordPolicyException",
    "RateLimitException",
    "SudoLockoutError",
    "CSRFException",
]


class CustomException(HTTPException):
    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail: Any = None,
        headers: dict[str, str] | None = None,
    ):
        if not detail:
            detail = HTTPStatus(status_code).description
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class BadRequestException(CustomException):
    def __init__(self, detail: str | None = None):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class OAuthAccountException(BadRequestException):
    """A ``400`` refusing an OAuth sign-in while resolving the account.

    ``code`` is the machine-readable reason the OAuth callback reports as
    ``error`` (``email_missing``, ``email_unverified``, ``email_too_long``,
    ``provider_already_linked``); ``detail`` is the human-readable message.
    """

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(detail)


class NotFoundException(CustomException):
    def __init__(self, detail: str | None = None):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class ForbiddenException(CustomException):
    def __init__(self, detail: str | None = None):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class UnauthorizedException(CustomException):
    def __init__(self, detail: str | None = None):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class UnprocessableEntityException(CustomException):
    def __init__(self, detail: str | None = None):
        super().__init__(status_code=422, detail=detail)


class DuplicateValueException(CustomException):
    def __init__(self, detail: str | None = None):
        super().__init__(status_code=422, detail=detail)


class ValueTooLongException(CustomException):
    """A ``422`` in FastAPI's validation-error format, one ``string_too_long`` entry per field."""

    def __init__(self, limits: dict[str, int]):
        super().__init__(
            status_code=422,
            detail=[
                {
                    "type": "string_too_long",
                    "loc": ["body", field],
                    "msg": f"String should have at most {limit} characters",
                    "ctx": {"max_length": limit},
                }
                for field, limit in limits.items()
            ],
        )


class PasswordPolicyException(CustomException):
    """A ``422`` in FastAPI's validation-error format, one entry per unmet password rule."""

    def __init__(self, field: str, errors: list[dict[str, Any]]):
        self.errors = [
            {
                "type": error["type"],
                "loc": ["body", field],
                **{key: value for key, value in error.items() if key != "type"},
            }
            for error in errors
        ]
        super().__init__(status_code=422, detail=self.errors)


class RateLimitException(CustomException):
    def __init__(
        self,
        detail: str | None = None,
        retry_after: int | None = None,
        headers: dict[str, str] | None = None,
    ):
        merged = dict(headers or {})
        if retry_after is not None:
            merged["Retry-After"] = str(retry_after)
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers=merged or None,
        )


class SudoLockoutError(CustomException):
    """Raised when too many wrong-password sudo attempts lock re-authentication.

    Distinct from [RateLimitException][crudauth.exceptions.RateLimitException]
    (its own ``sudo:*`` counter, separate from login lockout) but shares the
    429 + ``Retry-After`` shape.
    """

    def __init__(self, detail: str | None = None, retry_after: int | None = None):
        headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers=headers,
        )


class CSRFException(CustomException):
    """Raised when CSRF validation fails on an unsafe (mutating) request."""

    def __init__(self, detail: str = "CSRF token validation failed"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            headers={"X-CSRF-Error": "true"},
        )

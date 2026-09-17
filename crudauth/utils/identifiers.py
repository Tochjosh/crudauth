"""Canonical forms of the values accounts are looked up and keyed by."""

from __future__ import annotations

from typing import overload

__all__ = ["canonical_email", "canonical_identifier", "mask_email"]


@overload
def canonical_email(email: str) -> str: ...
@overload
def canonical_email(email: None) -> None: ...
def canonical_email(email: str | None) -> str | None:
    """Normalize an email for storage/comparison (trim + lowercase).

    Ensures a user created via Google as ``Foo@x.com`` can log in by password as
    ``foo@x.com`` without surprises.
    """
    if email is None:
        return None
    return email.strip().lower()


def mask_email(email: str) -> str:
    """Mask an email for display: ``john@example.com`` -> ``j***@example.com``.

    A display helper for shoulder-surfing / casual logs - **not** a security
    control (it's obfuscation, not a guarantee). Returns ``"***"`` when there's
    no ``@``; keeps only the first local-part character (so a single-char local
    part can't leak more than that one character).

    Example:
        ```python
        mask_email("john@example.com")  # "j***@example.com"
        mask_email("a@x.io")            # "a***@x.io"
        mask_email("not-an-email")      # "***"
        ```
    """
    if not email or "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        return f"{local}***@{domain}"
    return f"{local[0]}***@{domain}"


def canonical_identifier(identifier: str) -> str:
    """Normalize a login identifier into its lockout key (trim + casefold).

    Case variants of one identifier (``v@x.com`` / ``V@x.com``, ``bob`` / ``BOB``)
    collapse to a single key, so an attacker can't reset the per-username counter
    by varying the case while a case-insensitive lookup or collation still
    reaches the same account. A key coarser than the lookup only makes the
    lockout stricter.
    """
    return identifier.strip().casefold()

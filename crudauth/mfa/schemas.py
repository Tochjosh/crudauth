"""Stored state for MFA login challenges."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

__all__ = ["MfaChallenge"]


class MfaChallenge(BaseModel):
    """A login waiting for its second factor, stored under the hash of its token.

    The user is ``account_id`` rather than ``user_id``, which session storage would
    index per user. ``token_version`` is the user's at the password check, so a
    password reset or change before the code is entered voids the challenge.

    ``options`` carries what the transport needs to finish the login (``remember_me``
    for a session, ``scopes`` for a token, session ``metadata``, ``redirect_to``).
    """

    account_id: Any
    token_version: int
    transport: str
    setup: bool = False
    lockout_identifier: str
    ip_address: str
    options: dict[str, Any] = Field(default_factory=dict)
    attempts: int = 0

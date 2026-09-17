"""Stored state for MFA login challenges."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

__all__ = ["MfaChallenge"]


class MfaChallenge(BaseModel):
    """A login waiting for its second factor, stored under the hash of its token.

    ``options`` carries what the transport needs to finish the login (``remember_me``
    for a session, ``scopes`` for a token, session ``metadata``, ``redirect_to``).
    """

    user_id: Any
    transport: str
    setup: bool = False
    lockout_identifier: str
    ip_address: str
    options: dict[str, Any] = Field(default_factory=dict)
    attempts: int = 0

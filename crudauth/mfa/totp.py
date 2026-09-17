"""RFC 6238 time-based one-time passwords (HMAC-SHA1, 6 digits, 30-second steps)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import quote, urlencode

from .constants import TOTP_DIGITS, TOTP_DRIFT_STEPS, TOTP_PERIOD_SECONDS, TOTP_SECRET_BYTES

__all__ = ["generate_secret", "provisioning_uri", "totp_code", "normalize_code", "matching_step"]

_CODE_PATTERN = re.compile(rf"[0-9]{{{TOTP_DIGITS}}}")


def generate_secret() -> str:
    """A new random TOTP secret, base32-encoded without padding."""
    return base64.b32encode(secrets.token_bytes(TOTP_SECRET_BYTES)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def totp_code(secret: str, step: int) -> str:
    """The code for ``secret`` at time step ``step``."""
    digest = hmac.new(_key(secret), step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def normalize_code(code: str) -> str | None:
    """The code with spaces removed, or ``None`` unless it is exactly six ASCII digits."""
    compact = code.replace(" ", "")
    return compact if _CODE_PATTERN.fullmatch(compact) else None


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """The time step ``code`` belongs to, within one step of drift, or ``None``.

    Every candidate step is compared in constant time, so the check takes the same
    time whichever step matches.
    """
    normalized = normalize_code(code)
    if normalized is None:
        return None
    current = int((time.time() if now is None else now) // TOTP_PERIOD_SECONDS)
    matched = None
    for step in range(current - TOTP_DRIFT_STEPS, current + TOTP_DRIFT_STEPS + 1):
        if hmac.compare_digest(totp_code(secret, step), normalized):
            matched = step
    return matched


def provisioning_uri(secret: str, *, issuer: str, account: str) -> str:
    """The ``otpauth://`` URI an authenticator app reads from a QR code."""
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD_SECONDS,
        },
        quote_via=quote,
    )
    return f"otpauth://totp/{label}?{query}"

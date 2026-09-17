"""Single-use recovery codes, stored as SHA-256 hashes."""

from __future__ import annotations

import hashlib
import json
import secrets

from .constants import (
    RECOVERY_CODE_ALPHABET,
    RECOVERY_CODE_COUNT,
    RECOVERY_CODE_GROUP_LENGTH,
    RECOVERY_CODE_GROUPS,
)

__all__ = ["generate_recovery_codes", "hash_recovery_codes", "load_hashes", "hash_recovery_code"]


def _normalize(code: str) -> str:
    return "".join(ch for ch in code.lower() if ch not in " -")


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(_normalize(code).encode()).hexdigest()


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """``count`` codes like ``abcd-efgh-jkmn-pqrs`` (about 79 bits each)."""
    return [
        "-".join(
            "".join(
                secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(RECOVERY_CODE_GROUP_LENGTH)
            )
            for _ in range(RECOVERY_CODE_GROUPS)
        )
        for _ in range(count)
    ]


def hash_recovery_codes(codes: list[str]) -> str:
    """The stored form of ``codes``: a JSON list of their hashes."""
    return json.dumps([hash_recovery_code(code) for code in codes])


def load_hashes(stored: str | None) -> list[str]:
    if not stored:
        return []
    try:
        hashes = json.loads(stored)
    except ValueError:
        return []
    return [value for value in hashes if isinstance(value, str)] if isinstance(hashes, list) else []

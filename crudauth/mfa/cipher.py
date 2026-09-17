"""Encryption at rest for TOTP secrets (Fernet, rotatable with several keys)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

__all__ = ["SecretCipher"]


def _require_cryptography() -> Any:
    try:
        from cryptography import fernet
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "MFA requires the 'cryptography' package. Install with: pip install 'crudauth[mfa]'"
        ) from exc
    return fernet


class SecretCipher:
    """Encrypts with the first key and decrypts with any of them.

    Raises:
        ValueError: If a key isn't a Fernet key.
    """

    def __init__(self, keys: Sequence[str]):
        fernet = _require_cryptography()
        try:
            self._fernet = fernet.MultiFernet([fernet.Fernet(key) for key in keys])
        except ValueError as exc:
            raise ValueError(
                "MfaConfig.encryption_key must be a Fernet key (32 url-safe base64-encoded "
                'bytes). Generate one with: python -c "from cryptography.fernet import '
                'Fernet; print(Fernet.generate_key().decode())"'
            ) from exc
        self._invalid_token = fernet.InvalidToken

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str | None:
        """The plaintext, or ``None`` when ``token`` was tampered with or no key matches."""
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except self._invalid_token:
            return None

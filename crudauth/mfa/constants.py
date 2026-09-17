"""Constants for TOTP multi-factor authentication."""

from __future__ import annotations

from ..constants import SECONDS_PER_MINUTE

TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
TOTP_DRIFT_STEPS = 1
TOTP_SECRET_BYTES = 20

RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_GROUPS = 4
RECOVERY_CODE_GROUP_LENGTH = 4
RECOVERY_CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"

DEFAULT_CHALLENGE_TTL_SECONDS = 5 * SECONDS_PER_MINUTE
DEFAULT_MAX_CODE_ATTEMPTS = 5
CHALLENGE_TOKEN_BYTES = 32
CHALLENGE_STORAGE_PREFIX = "mfa_challenge:"

MFA_FIELDS = (
    "totp_secret_encrypted",
    "totp_confirmed_at",
    "totp_last_step",
    "mfa_recovery_codes",
)

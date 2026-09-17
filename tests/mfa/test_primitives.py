"""TOTP codes, secret encryption and recovery codes."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet

from crudauth.mfa.cipher import SecretCipher
from crudauth.mfa.recovery import (
    generate_recovery_codes,
    hash_recovery_code,
    hash_recovery_codes,
    load_hashes,
)
from crudauth.mfa.totp import (
    generate_secret,
    matching_step,
    normalize_code,
    provisioning_uri,
    totp_code,
)

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    ("unix_time", "code"),
    [(59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")],
)
def test_codes_match_the_rfc_6238_sha1_vectors(unix_time: int, code: str) -> None:
    assert totp_code(RFC_SECRET, unix_time // 30) == code


def test_a_code_is_accepted_within_one_step_of_drift() -> None:
    now = 1_000_000_000.0
    step = int(now // 30)

    assert matching_step(RFC_SECRET, totp_code(RFC_SECRET, step), now) == step
    assert matching_step(RFC_SECRET, totp_code(RFC_SECRET, step - 1), now) == step - 1
    assert matching_step(RFC_SECRET, totp_code(RFC_SECRET, step + 1), now) == step + 1
    assert matching_step(RFC_SECRET, totp_code(RFC_SECRET, step - 2), now) is None
    assert matching_step(RFC_SECRET, totp_code(RFC_SECRET, step + 2), now) is None


def test_only_six_ascii_digits_count_and_spaces_are_ignored() -> None:
    assert normalize_code("123 456") == "123456"
    assert normalize_code(" 123456 ") == "123456"
    assert normalize_code("１２３４５６") is None
    assert normalize_code("١٢٣٤٥٦") is None
    assert normalize_code("12345") is None
    assert normalize_code("1234567") is None
    assert normalize_code("12345a") is None


def test_full_width_digits_of_a_valid_code_are_rejected() -> None:
    now = 1_000_000_000.0
    code = totp_code(RFC_SECRET, int(now // 30))
    full_width = "".join(chr(ord(digit) + 0xFEE0) for digit in code)

    assert matching_step(RFC_SECRET, full_width, now) is None


def test_generated_secrets_are_random_base32() -> None:
    first, second = generate_secret(), generate_secret()

    assert first != second
    assert len(base64.b32decode(first + "=" * (-len(first) % 8))) == 20


def test_the_provisioning_uri_carries_the_secret_issuer_and_account() -> None:
    uri = urlparse(provisioning_uri("ABC234", issuer="Acme Inc", account="a@x.com"))

    assert (uri.scheme, uri.netloc) == ("otpauth", "totp")
    assert uri.path == "/Acme%20Inc%3Aa%40x.com"
    assert parse_qs(uri.query) == {
        "secret": ["ABC234"],
        "issuer": ["Acme Inc"],
        "algorithm": ["SHA1"],
        "digits": ["6"],
        "period": ["30"],
    }


def test_secrets_round_trip_and_tampering_is_rejected() -> None:
    cipher = SecretCipher([Fernet.generate_key().decode()])
    token = cipher.encrypt("SECRET")

    assert token != "SECRET"
    assert cipher.decrypt(token) == "SECRET"
    assert cipher.decrypt(token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")) is None
    assert cipher.decrypt("not-a-token") is None


def test_a_rotated_key_still_decrypts_old_secrets() -> None:
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    token = SecretCipher([old_key]).encrypt("SECRET")

    assert SecretCipher([new_key, old_key]).decrypt(token) == "SECRET"
    assert SecretCipher([new_key]).decrypt(token) is None


def test_an_invalid_key_is_refused() -> None:
    with pytest.raises(ValueError, match="Fernet key"):
        SecretCipher(["not-a-fernet-key"])


def test_recovery_codes_are_unique_and_match_however_they_are_typed() -> None:
    codes = generate_recovery_codes(10)

    assert len(set(codes)) == 10
    assert all(len(code) == 19 and code.count("-") == 3 for code in codes)
    assert hash_recovery_code(codes[0]) == hash_recovery_code(codes[0].upper().replace("-", " "))
    assert load_hashes(hash_recovery_codes(codes)) == [hash_recovery_code(code) for code in codes]
    assert load_hashes("not json") == []
    assert load_hashes(None) == []

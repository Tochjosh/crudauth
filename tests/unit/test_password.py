"""Unit tests for password hashing, verification, and the unusable sentinel."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

import bcrypt
import pytest

from crudauth.utils import (
    _bcrypt_input,
    dummy_verify_password,
    get_password_hash,
    get_password_hash_async,
    make_unusable_password,
    verify_and_update_password,
    verify_and_update_password_async,
    verify_password,
    verify_password_async,
)


def test_password_roundtrip() -> None:
    h = get_password_hash("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)


def test_verify_password_handles_malformed_hash() -> None:
    assert verify_password("anything", "not-a-bcrypt-hash") is False


def test_unusable_password_never_verifies() -> None:
    sentinel = make_unusable_password()
    assert not verify_password("", sentinel)
    assert not verify_password("password", sentinel)


def test_long_password_not_truncated_at_72_bytes() -> None:
    # Two passwords sharing a 72-byte prefix must NOT be interchangeable
    # (bcrypt alone truncates at 72 bytes; the SHA-256 pre-hash prevents it).
    base = "a" * 72
    h = get_password_hash(base + "X")
    assert verify_password(base + "X", h)
    assert not verify_password(base + "Y", h)
    assert not verify_password(base, h)


def test_password_roundtrip_very_long() -> None:
    pw = "correct horse battery staple " * 10
    assert verify_password(pw, get_password_hash(pw))


def test_dummy_verify_password_runs_without_raising() -> None:
    # Exercises the absent-user timing-equalization path; must not raise.
    dummy_verify_password("whatever")


PRECOMPOSED = "caf\u00e9-secret"
COMBINING = "cafe\u0301-secret"


def _hash_before_normalization(password: str) -> str:
    return bcrypt.hashpw(_bcrypt_input(password), bcrypt.gensalt()).decode()


def _elapsed(check: Callable[[], object]) -> float:
    start = time.perf_counter()
    check()
    return time.perf_counter() - start


def test_verify_password_returns_false_for_a_missing_hash() -> None:
    assert verify_password("anything", None) is False


def test_precomposed_and_combining_forms_verify_against_each_other() -> None:
    assert verify_password(COMBINING, get_password_hash(PRECOMPOSED))
    assert verify_password(PRECOMPOSED, get_password_hash(COMBINING))


def test_hash_from_before_normalization_keeps_verifying() -> None:
    legacy = _hash_before_normalization(COMBINING)
    assert verify_password(COMBINING, legacy)
    assert not verify_password("cafe-secret", legacy)


def test_verify_and_update_password_rehashes_only_a_pre_normalization_match() -> None:
    verified, new_hash = verify_and_update_password(
        COMBINING, _hash_before_normalization(COMBINING)
    )
    assert verified is True
    assert new_hash is not None
    assert bcrypt.checkpw(_bcrypt_input(PRECOMPOSED), new_hash.encode())

    assert verify_and_update_password(COMBINING, get_password_hash(PRECOMPOSED)) == (True, None)
    assert verify_and_update_password("hunter2", get_password_hash("hunter2")) == (True, None)
    assert verify_and_update_password("wrong", get_password_hash(PRECOMPOSED)) == (False, None)
    assert verify_and_update_password("wrong", None) == (False, None)


@pytest.mark.parametrize(
    "stored", [make_unusable_password(), "", None, "not-a-bcrypt-hash"], ids=repr
)
def test_unverifiable_hash_costs_a_full_verification(stored: str | None) -> None:
    real_hash = get_password_hash("hunter2")
    dummy_verify_password("warm-up")
    real = _elapsed(lambda: verify_password("wrong", real_hash))
    assert _elapsed(lambda: verify_password("wrong", stored)) > real / 2


async def test_async_helpers_match_the_sync_ones() -> None:
    hashed = await get_password_hash_async(PRECOMPOSED)
    assert await verify_password_async(COMBINING, hashed)
    assert not await verify_password_async("wrong", hashed)
    verified, new_hash = await verify_and_update_password_async(
        COMBINING, _hash_before_normalization(COMBINING)
    )
    assert verified is True
    assert new_hash is not None


async def test_async_verify_keeps_the_event_loop_responsive() -> None:
    hashed = get_password_hash("hunter2")
    blocking = _elapsed(lambda: verify_password("hunter2", hashed))
    verify = asyncio.ensure_future(verify_password_async("hunter2", hashed))
    longest_gap = 0.0
    last = time.perf_counter()
    while not verify.done():
        await asyncio.sleep(0.005)
        now = time.perf_counter()
        longest_gap = max(longest_gap, now - last)
        last = now
    assert verify.result() is True
    assert longest_gap < blocking / 2

"""Password hashing and verification, and the unusable-password sentinel."""

from __future__ import annotations

import base64
import functools
import hashlib
import secrets
import unicodedata

import bcrypt
from fastapi.concurrency import run_in_threadpool

__all__ = [
    "normalize_password",
    "get_password_hash",
    "get_password_hash_async",
    "verify_password",
    "verify_password_async",
    "verify_and_update_password",
    "verify_and_update_password_async",
    "dummy_verify_password",
    "make_unusable_password",
    "is_unusable_password",
]


def _bcrypt_input(password: str) -> bytes:
    """Length-normalize the password for bcrypt; not the password hash itself.

    bcrypt silently ignores input past 72 bytes, which would make two long
    passwords sharing a 72-byte prefix interchangeable. Hashing to SHA-256 and
    base64-encoding yields a fixed 44-byte value (well under 72) that depends on
    every byte typed, so the bcrypt comparison covers the whole password.

    Note:
        The actual password KDF is bcrypt (slow, salted, in [get_password_hash]
        [crudauth.utils.get_password_hash]); this SHA-256 step is only a
        fixed-width transform and is never stored or relied on for slowness. A
        static analyzer may flag the SHA-256 call as "weak password hashing" -
        that is a false positive, since the stored hash is bcrypt, not this
        digest. This is the same construction Django and passlib use.
    """
    digest = hashlib.sha256(password.encode()).digest()
    return base64.b64encode(digest)


def normalize_password(password: str) -> str:
    """Unicode-normalize a password (NFKC) so every way of typing it hashes the same.

    ``é`` typed as one precomposed code point and as ``e`` plus a combining accent
    normalize to the same string, as NIST SP 800-63B recommends.
    """
    return unicodedata.normalize("NFKC", password)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password with bcrypt (random salt per call).

    The password is NFKC-normalized (see [normalize_password]
    [crudauth.utils.normalize_password]) and SHA-256 pre-hashed before bcrypt
    (see [_bcrypt_input][crudauth.utils.hashing._bcrypt_input]), so there is no effective
    length ceiling and no silent truncation. This call blocks for the bcrypt
    work; use [get_password_hash_async][crudauth.utils.get_password_hash_async]
    inside an async route.

    Example:
        ```python
        await auth.repo.create(db, {"email": e, "hashed_password": get_password_hash(pw)})
        ```
    """
    hashed: bytes = bcrypt.hashpw(_bcrypt_input(normalize_password(password)), bcrypt.gensalt())
    return hashed.decode()


async def get_password_hash_async(password: str) -> str:
    """[get_password_hash][crudauth.utils.get_password_hash] in a worker thread, off the event loop.

    Example:
        ```python
        hashed = await get_password_hash_async(pw)
        await auth.repo.update(db, user, {"hashed_password": hashed})
        ```
    """
    return await run_in_threadpool(get_password_hash, password)


def _checkpw(password: str, hashed_password: str | None) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_input(password), (hashed_password or "").encode())
    except (ValueError, TypeError):
        bcrypt.checkpw(_bcrypt_input(""), _dummy_hash().encode())
        return False


def _matching_form(plain_password: str, hashed_password: str | None) -> str | None:
    normalized = normalize_password(plain_password)
    if _checkpw(normalized, hashed_password):
        return normalized
    if plain_password != normalized and _checkpw(plain_password, hashed_password):
        return plain_password
    return None


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """Verify a plaintext password against a bcrypt hash.

    The NFKC-normalized password is checked first, then the password as typed,
    so hashes created before normalization keep verifying.

    Returns ``False`` (rather than raising) when the stored hash is missing,
    empty, the unusable sentinel, or malformed, so a corrupted row produces a
    clean "invalid password" path instead of a 500. Those cases still pay a full
    bcrypt verification, so an account without a verifiable hash answers in the
    same time as one with a real hash. This call blocks for the bcrypt work; use
    [verify_password_async][crudauth.utils.verify_password_async] inside an async
    route.

    Example:
        ```python
        if not verify_password(form.password, auth.repo.get(user, "hashed_password")):
            raise UnauthorizedException("Incorrect username or password")
        ```
    """
    return _matching_form(plain_password, hashed_password) is not None


async def verify_password_async(plain_password: str, hashed_password: str | None) -> bool:
    """[verify_password][crudauth.utils.verify_password] in a worker thread, off the event loop.

    Example:
        ```python
        if not await verify_password_async(form.password, auth.repo.get(user, "hashed_password")):
            raise UnauthorizedException("Incorrect username or password")
        ```
    """
    return await run_in_threadpool(verify_password, plain_password, hashed_password)


def verify_and_update_password(
    plain_password: str, hashed_password: str | None
) -> tuple[bool, str | None]:
    """Verify a password and return a replacement hash when the stored one predates normalization.

    Verification is the same as [verify_password][crudauth.utils.verify_password].

    Returns:
        ``(verified, new_hash)``. ``new_hash`` is a fresh hash of the normalized
        password when the stored hash only matched the password as typed (a hash
        created before normalization), and ``None`` otherwise.

    Example:
        ```python
        verified, new_hash = verify_and_update_password(pw, auth.repo.get(user, "hashed_password"))
        if verified and new_hash is not None:
            await auth.repo.update(db, user, {"hashed_password": new_hash})
        ```
    """
    matched = _matching_form(plain_password, hashed_password)
    if matched is None:
        return False, None
    if matched == normalize_password(plain_password):
        return True, None
    return True, get_password_hash(plain_password)


async def verify_and_update_password_async(
    plain_password: str, hashed_password: str | None
) -> tuple[bool, str | None]:
    """[verify_and_update_password][crudauth.utils.verify_and_update_password] in a worker thread, off the event loop."""
    return await run_in_threadpool(verify_and_update_password, plain_password, hashed_password)


@functools.cache
def _dummy_hash() -> str:
    """A real bcrypt hash of a random value, computed once and cached.

    Used to equalize login timing: see [dummy_verify_password]
    [crudauth.utils.dummy_verify_password].
    """
    return get_password_hash(secrets.token_urlsafe(32))


def dummy_verify_password(plain_password: str) -> None:
    """Run a throwaway bcrypt verification and discard the result.

    For a hand-written flow's user-not-found branch, so the absent-user path
    pays the same bcrypt cost as the existing-user path; without it, a missing
    account returns measurably faster and becomes a user-enumeration oracle.
    [verify_password][crudauth.utils.verify_password] with a ``None`` hash does
    the same work.
    """
    verify_password(plain_password, _dummy_hash())


def make_unusable_password() -> str:
    """Return a sentinel that no input can ever verify against.

    Used for OAuth-only accounts. The leading ``!`` makes the value an invalid
    bcrypt hash, so [verify_password][crudauth.utils.verify_password] always returns ``False`` for it. The
    random suffix makes every sentinel unique. Mirrors Django's
    ``set_unusable_password``.

    Example:
        ```python
        # an OAuth-created account with no password yet
        await auth.repo.create(db, {"email": e, "hashed_password": make_unusable_password()})
        ```
    """
    return "!" + secrets.token_urlsafe(16)


def is_unusable_password(hashed_password: str) -> bool:
    """Whether ``hashed_password`` is the unusable sentinel (or empty).

    ``True`` means the account has no real password set - an OAuth-only account
    (see [make_unusable_password][crudauth.utils.make_unusable_password], whose
    sentinel starts with ``!``, never a valid bcrypt hash).

    Example:
        ```python
        if is_unusable_password(auth.repo.get(user, "hashed_password", "")):
            ...  # OAuth-only: offer /set-password rather than a password change
        ```
    """
    return not hashed_password or hashed_password.startswith("!")

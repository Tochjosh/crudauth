"""The password login step both built-in transports run before they hand out credentials."""

from typing import Any

from fastapi import Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from ..core import Transport

__all__ = ["password_login"]


async def password_login(
    transport: Transport,
    *,
    db: Any,
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm,
    options: dict[str, Any],
) -> Any:
    """Verify the credentials, raise the MFA challenge when one is due, else complete the login.

    Returns the challenge body when MFA is configured and the account is enrolled;
    the login is finished by ``POST /mfa/verify`` with the same ``options``.
    Otherwise it returns whatever the transport's ``complete_login`` returns: the
    session cookies, or the token pair.
    """
    runtime = transport.runtime
    user = await runtime.authenticate_password(
        db,
        form_data.username,
        form_data.password,
        request=request,
        record_success=runtime.mfa is None,
    )
    if runtime.mfa is not None:
        challenge = await runtime.mfa.challenge_login(
            db,
            user,
            request=request,
            transport=transport.name,
            lockout_identifier=form_data.username,
            options=options,
        )
        if challenge is not None:
            return challenge
    return await transport.complete_login(request, response, user, options)

"""The bearer transport's own routes: ``/token``, ``/refresh`` and the cookie ``/logout``."""

from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from ...exceptions import ForbiddenException, UnauthorizedException
from ...utils import is_cross_site
from ..login import password_login
from .constants import (
    REFRESH_LOCATION_COOKIE,
    TOKEN_TYPE_BEARER,
    TOKEN_VERSION_CLAIM,
)
from .tokens import TokenType, verify_token

if TYPE_CHECKING:  # pragma: no cover
    from .transport import BearerTransport

__all__ = ["build_bearer_routes"]


def build_bearer_routes(transport: "BearerTransport") -> APIRouter:
    """Build the routes a bound [BearerTransport][crudauth.transports.bearer.transport.BearerTransport] contributes."""
    router = APIRouter(tags=["auth"])
    runtime = transport.runtime
    db_dep = runtime.db_dependency

    @router.post("/token")
    async def issue_token(
        request: Request,
        response: Response,
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Exchange username/email + password for an access token.

        Returns ``{"access_token", "token_type"}``; the refresh token is set
        as an httpOnly cookie or returned in the body per ``refresh=``.
        Subject to the shared login lockout.

        With ``refresh="cookie"``, a request the browser marks
        ``Sec-Fetch-Site: cross-site`` gets a 403, so another site can't plant
        its refresh cookie in the visitor's browser.

        Note:
            A disabled account returns the same "Incorrect username or
            password" as bad credentials (no exists-but-disabled oracle for a
            credential holder); the real reason is logged server-side
            (``reason=disabled``).
        """
        if transport.refresh == REFRESH_LOCATION_COOKIE and is_cross_site(request):
            raise ForbiddenException("Cross-site login requests are not allowed.")
        return await password_login(
            transport,
            db=db,
            request=request,
            response=response,
            form_data=form_data,
            options={"scopes": form_data.scopes},
        )

    @router.post("/refresh")
    async def refresh_token(request: Request, db: Annotated[Any, Depends(db_dep)]):
        """Mint a fresh access token from a valid refresh token (cookie or body)."""
        token = await transport.read_refresh(request)
        if not token:
            raise UnauthorizedException("Refresh token missing")
        payload = verify_token(
            token, runtime.secret_key, TokenType.REFRESH, algorithm=runtime.algorithm
        )
        if payload is None:
            raise UnauthorizedException("Invalid or expired refresh token")
        user = await runtime.repo.get_by_id(db, payload["sub"])
        if user is None or not runtime.repo.is_active(user):
            raise UnauthorizedException("Invalid or expired refresh token")
        if payload.get(TOKEN_VERSION_CLAIM, 0) != runtime.repo.token_version(user):
            raise UnauthorizedException("Invalid or expired refresh token")
        scopes = transport.clamp_scopes(payload.get("scopes") or ())
        access = transport.access_token(user, scopes)
        return {"access_token": access, "token_type": TOKEN_TYPE_BEARER}

    if transport.refresh == REFRESH_LOCATION_COOKIE and not any(
        other.name == "session" for other in runtime.transports
    ):

        @router.post("/logout")
        async def logout(response: Response):
            """Clear the refresh-token cookie. With a session transport, its ``/logout`` does this."""
            transport.clear_cookies(response)
            return {"detail": "Logged out"}

    return router

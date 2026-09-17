"""The opt-in session and CSRF management routes (``SessionTransport(management_routes=True)``)."""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from ...exceptions import BadRequestException, NotFoundException, UnauthorizedException
from ...principal import Principal
from ...ratelimit import KeyBy
from .constants import REMEMBER_ME_META_KEY
from .manager import SessionManager

__all__ = ["SessionInfo", "build_session_management_router"]


class SessionInfo(BaseModel):
    """One active session, as returned by ``GET /sessions`` (the opt-in management route).

    ``id`` is the session's public handle (the SHA-256 of its id), what
    ``DELETE /sessions/{id}`` takes; the session id itself is the cookie value and
    is never returned. ``device`` is the parsed user-agent info (browser/os/device
    flags), empty when UA parsing isn't available; timestamps serialize to ISO-8601.

    Example:
        ```python
        # each entry in the GET /sessions response:
        SessionInfo(
            id="5d41...",
            device={"browser": "Chrome", "os": "macOS", "is_mobile": False},
            ip="203.0.113.7",
            created_at=created, last_activity=seen, current=True,
        )
        ```
    """

    id: str
    device: dict[str, Any] = Field(default_factory=dict)
    ip: str = ""
    created_at: datetime
    last_activity: datetime
    current: bool = False


def build_session_management_router(auth: Any, sessions: SessionManager) -> APIRouter:
    """Build ``/logout-all``, ``/sessions``, ``DELETE /sessions/{id}`` and ``/csrf/refresh``.

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth].
        sessions: The session transport's [SessionManager][crudauth.transports.session.manager.SessionManager].

    Returns:
        An `APIRouter` with the management routes.
    """
    router = APIRouter(tags=["auth"])
    session_user = auth.current_user(transport="session")

    @router.post(
        "/logout-all",
        dependencies=[Depends(auth.rate_limit("logout_all", key=KeyBy.USER))],
    )
    async def logout_all(
        response: Response,
        principal: Annotated[Principal, Depends(session_user)],
        keep_current: bool = False,
    ):
        """Sign out of all sessions. ``keep_current=True`` keeps the calling session."""
        current_sid = principal.metadata.get("session_id")
        revoked = await sessions.revoke_all(
            principal.user_id, exclude=current_sid if keep_current else None
        )
        if not keep_current:
            sessions.clear_session_cookies(response)
        return {"detail": "Signed out of all sessions.", "revoked": revoked}

    @router.get("/sessions", response_model=list[SessionInfo])
    async def list_sessions(principal: Annotated[Principal, Depends(session_user)]):
        """List the user's active sessions. ``[]`` if the backend can't index by user."""
        return await sessions.list_for_user(
            principal.user_id, current_session_id=principal.metadata.get("session_id")
        )

    @router.delete("/sessions/{session_handle}")
    async def revoke_session(
        session_handle: str,
        response: Response,
        principal: Annotated[Principal, Depends(session_user)],
    ):
        """Revoke one session by the ``id`` listed in ``GET /sessions`` (404 also covers 'not yours')."""
        if not await sessions.revoke_by_handle(session_handle, owner_id=principal.user_id):
            raise NotFoundException("Session not found.")
        current_sid = principal.metadata.get("session_id")
        if current_sid and sessions.session_handle(current_sid) == session_handle:
            sessions.clear_session_cookies(response)
        return {"detail": "Session revoked."}

    @router.post(
        "/csrf/refresh",
        dependencies=[Depends(auth.rate_limit("csrf_refresh", key=KeyBy.IP))],
    )
    async def csrf_refresh(request: Request, response: Response):
        """Re-mint the CSRF cookie when it's lost but the session is still valid.

        Note:
            Deliberately NOT behind ``current_user`` - requiring a valid CSRF
            header to refresh CSRF would defeat the recovery purpose. It
            resolves the session cookie directly. An attacker can *trigger*
            this cross-origin (the session cookie auto-rides) but cannot
            *read* the response or the new cookie (CORS), so they never learn
            the token; and the self-heal guard returns the existing token
            unchanged when it's already valid, so a triggered call never
            rotates a healthy token.
        """
        if sessions.csrf_storage is None:
            raise BadRequestException("CSRF is disabled.")
        session_id = request.cookies.get(sessions.session_cookie_name)
        session = await sessions.validate_session(session_id) if session_id else None
        if session is None or session_id is None:
            raise UnauthorizedException("Not authenticated")
        cookie = request.cookies.get(sessions.csrf_cookie_name)
        if cookie and await sessions.validate_csrf_token(session_id, cookie):
            return {"csrf_token": cookie}
        token = await sessions.regenerate_csrf_token(session_id)
        max_age = (
            sessions.timeout_seconds_for(session.metadata)
            if session.metadata.get(REMEMBER_ME_META_KEY)
            else None
        )
        sessions.set_csrf_cookie(response, token, max_age=max_age)
        return {"csrf_token": token}

    return router

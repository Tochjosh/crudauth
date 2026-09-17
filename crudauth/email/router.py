"""Builds the recovery-flow endpoints (verify / reset / change).

The trigger endpoints carry a per-IP rate-limit dependency (caller spray); the
service additionally enforces a silent per-target cap. The verify and reset
request bodies are shaped to the contract's recovery factor (``email`` validated
as an address, any other factor as a plain string), so a phone-recovery app can
drive them over HTTP with a phone number. Change-email is email-specific and only
mounts when the model actually has an email column and a channel emails the
recipient.
"""

from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, create_model

from ..protocols import AuthSurface
from ..principal import Principal
from ..ratelimit import KeyBy
from .service import EmailFlowService

__all__ = ["build_email_router"]


class _RedirectIn(BaseModel):
    """Requests that can carry where to send the person once they confirm."""

    redirect_to: str | None = None


class _TokenIn(BaseModel):
    token: str


class _ResetIn(BaseModel):
    token: str
    new_password: str


class _ChangeIn(_RedirectIn):
    new_email: EmailStr
    password: str


def _with_redirect(detail: str, redirect_to: str | None) -> dict[str, str]:
    """The confirm response, carrying ``redirect_to`` only when the token had one."""
    body = {"detail": detail}
    if redirect_to is not None:
        body["redirect_to"] = redirect_to
    return body


def build_email_router(*, auth: AuthSurface, service: EmailFlowService) -> APIRouter:
    """Build the recovery-flow router (verify / reset, plus change-email when applicable).

    The verify and reset request bodies are generated for the recovery factor: an
    email-recovery app keeps ``{"email": ...}`` (validated as an address), a
    phone-recovery app gets ``{"phone": ...}``. Change-email endpoints are added
    only when the model has an ``email`` column and a channel emails the
    recipient, since they prove a real address.

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth] (for ``session``,
            ``current_user``, and ``rate_limit`` dependencies).
        service: The [EmailFlowService][crudauth.email.service.EmailFlowService] that mints/verifies tokens.

    Returns:
        An `APIRouter` with the recovery endpoints.
    """
    router = APIRouter(tags=["auth:email"])
    db_dep = auth.session
    user_dep = auth.current_user()

    factor = service.repo.recovery
    if factor is None:
        raise RuntimeError("the recovery router requires a recovery factor (identity.recovery)")
    field_type: Any = EmailStr if factor == "email" else str
    fields: dict[str, Any] = {factor: (field_type, ...)}
    RecoveryRequestModel = create_model("RecoveryRequestIn", __base__=_RedirectIn, **fields)
    ResetModel = create_model(
        "_ResetIn", __base__=_ResetIn, new_password=(service.password_policy.body_field(), ...)
    )
    channel_noun = "email" if factor == "email" else "message"

    @router.post(
        "/email/verify-request",
        dependencies=[Depends(auth.rate_limit("email_verify_request", key=KeyBy.IP))],
    )
    async def request_verification(
        body: RecoveryRequestModel,  # type: ignore[valid-type]
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Send a verification link to the recovery factor. Always succeeds (no enumeration).

        ``redirect_to`` rides inside the signed token, so the person lands back
        where they started even when the link is opened on another device. Only
        same-origin relative paths survive; anything else is dropped.
        """
        await service.request_recovery_verification(
            db, getattr(body, factor), redirect_to=cast(_RedirectIn, body).redirect_to
        )
        return {"detail": f"If an account exists, a verification {channel_noun} has been sent."}

    @router.post("/email/verify-confirm")
    async def confirm_verification(body: _TokenIn, db: Annotated[Any, Depends(db_dep)]):
        """Confirm a verification token and mark the recovery factor verified."""
        result = await service.confirm_recovery_verification(db, body.token)
        return _with_redirect("Verified successfully.", result.redirect_to)

    @router.post(
        "/password/reset-request",
        dependencies=[Depends(auth.rate_limit("password_reset_request", key=KeyBy.IP))],
    )
    async def request_reset(
        body: RecoveryRequestModel,  # type: ignore[valid-type]
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Send a password-reset link to the recovery factor. Always succeeds (no enumeration).

        ``redirect_to`` is carried the same way as on verification.
        """
        await service.request_password_reset(
            db, getattr(body, factor), redirect_to=cast(_RedirectIn, body).redirect_to
        )
        return {"detail": f"If an account exists, a password reset {channel_noun} has been sent."}

    @router.post("/password/reset-confirm")
    async def reset(
        body: ResetModel,  # type: ignore[valid-type]
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Reset the password from a valid token and evict the user's other sessions."""
        reset_body = cast(_ResetIn, body)
        result = await service.reset_password(db, reset_body.token, reset_body.new_password)
        return _with_redirect("Password reset successfully.", result.redirect_to)

    if service.supports_email_change:

        @router.post(
            "/email/change-request",
            dependencies=[Depends(auth.rate_limit("email_change_request", key=KeyBy.IP))],
        )
        async def change_request(
            body: _ChangeIn,
            db: Annotated[Any, Depends(db_dep)],
            principal: Annotated[Principal, Depends(user_dep)],
        ):
            """Request an email change (authenticated; re-auth via current password)."""
            await service.request_email_change(
                db,
                principal.user,
                body.new_email,
                body.password,
                redirect_to=body.redirect_to,
            )
            return {"detail": "If the address is available, a confirmation email has been sent."}

        @router.post("/email/change-confirm")
        async def change_confirm(body: _TokenIn, db: Annotated[Any, Depends(db_dep)]):
            """Confirm an email-change token and apply the new address."""
            result = await service.confirm_email_change(db, body.token)
            return _with_redirect("Email changed successfully.", result.redirect_to)

    return router

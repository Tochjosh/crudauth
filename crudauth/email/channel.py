"""Delivery channels: route a recovery token over a medium (email is built in).

crudauth owns the token (mint, one-time-use, redemption); a [DeliveryChannel]
[crudauth.email.channel.DeliveryChannel] owns the medium and the copy. The
recovery flows hand each configured channel a [DeliveryIntent]
[crudauth.email.channel.DeliveryIntent] and fire them all best-effort, so an app
can route reset/verify over email, SMS, WhatsApp, push, or several at once.
[EmailChannel][crudauth.email.channel.EmailChannel] is the built-in one.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from .config import EmailConfig
from .constants import (
    SUBJECT_CHANGE,
    SUBJECT_EMAIL_CHANGED,
    SUBJECT_EXISTING_ACCOUNT,
    SUBJECT_RESET,
    SUBJECT_VERIFY,
    EmailKind,
)
from .sender import EmailContext

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["DeliveryKind", "DeliveryIntent", "DeliveryChannel", "EmailChannel"]

# The channel-facing name for the message kind. Aliased to EmailKind so there is
# one source of truth for the values, no translation layer.
DeliveryKind = EmailKind


@dataclass(frozen=True)
class DeliveryIntent:
    """A recovery message crudauth needs delivered.

    crudauth owns the token and its lifetime; the channel owns the medium and the
    copy. Read what you need off ``recipient`` / ``user``; do not assume email.

    Attributes:
        kind: Which message this is (``verify_email`` for an email-recovery verify,
            ``verify_recovery`` for any other factor, ``reset_password`` /
            ``change_email``, or the ``existing_account`` / ``email_changed``
            notices). A non-email channel branches on this to pick its own
            medium-appropriate copy.
        token: The signed token, or ``None`` for a notice (``existing_account``,
            ``email_changed``), which has no action.
        user: The logical-contract user dict (``repo.to_dict``); empty for the
            ``existing_account`` notice. Contract fields only, so an app column
            (``phone``, ``whatsapp_id``, ...) is NOT here - load it off the ``db``
            handed to [deliver][crudauth.email.channel.DeliveryChannel.deliver].
        recipient: Where the message is addressed. For verify, reset and
            ``existing_account`` it's the recovery factor's value (an email
            address for email recovery, a phone number for phone recovery). For
            ``change_email`` it's the NEW email address, and only channels with
            ``sends_email`` receive that kind, since its token must reach that
            address and nothing else. For ``email_changed`` it's the previous
            email address.
        expires_in: Token lifetime in seconds (``0`` when ``token`` is ``None``).
    """

    kind: DeliveryKind
    token: str | None
    user: dict[str, Any]
    recipient: str
    expires_in: int


class DeliveryChannel(ABC):
    """A medium crudauth routes a recovery message over.

    crudauth fires every configured channel best-effort and swallows failures per
    channel, so raise freely on failure (it never surfaces and never stops the
    next channel). Reliability (retry/queue) belongs inside a channel.

    Attributes:
        sends_email: Whether this channel emails ``intent.recipient``. Only such
            channels receive ``change_email``, and change-email mounts only when
            one is configured. [EmailChannel][crudauth.email.channel.EmailChannel]
            sets it; set it on a custom channel that emails the recipient.

    Example:
        ```python
        class SMSChannel(DeliveryChannel):
            async def deliver(self, intent: DeliveryIntent, db) -> None:
                if intent.kind != "reset_password" or intent.token is None or db is None:
                    return
                user = await db.get(User, intent.user["id"])   # an app column
                if user and user.phone:
                    await sms.enqueue(to=user.phone, token=intent.token)  # hand off
        ```
    """

    sends_email: ClassVar[bool] = False

    @abstractmethod
    async def deliver(self, intent: DeliveryIntent, db: AsyncSession | None) -> None:
        """Route, render, and send ``intent``.

        Raise on failure (crudauth swallows per channel). Must not assume email;
        read ``intent.recipient`` / ``intent.user``.

        ``db`` is the request-scoped session for verify / reset / change and the
        ``email_changed`` notice, or ``None`` for the ``existing_account`` notice. Use it
        to load an app column you need (e.g.
        ``await db.get(User, intent.user["id"])`` for a phone number). It must be
        used **synchronously** and never committed or captured for deferred work:
        it is closed when the request ends, so a queued job that kept it would use
        a dead session. Read what you need, then enqueue the actual delivery.
        """
        raise NotImplementedError


# kind -> (subject, EmailConfig path attribute, body prefix) for the link kinds.
_EMAIL_SPECS: dict[str, tuple[str, str, str]] = {
    "verify_email": (SUBJECT_VERIFY, "verify_path", "Verify your email:"),
    "verify_recovery": (SUBJECT_VERIFY, "verify_path", "Verify your email:"),
    "reset_password": (SUBJECT_RESET, "reset_path", "Reset your password:"),
    "change_email": (SUBJECT_CHANGE, "change_path", "Confirm your new email:"),
}

_EMAIL_NOTICES: dict[str, tuple[str, str]] = {
    "existing_account": (
        SUBJECT_EXISTING_ACCOUNT,
        "Someone tried to register with this email. You already have an account - "
        "sign in or reset your password at {frontend_url}.",
    ),
    "email_changed": (
        SUBJECT_EMAIL_CHANGED,
        "The email address on your account was changed. If you didn't make this "
        "change, sign in at {frontend_url} to secure your account.",
    ),
}


class EmailChannel(DeliveryChannel):
    """The built-in channel: renders crudauth's recovery copy and calls the
    [EmailSender][crudauth.email.sender.EmailSender].

    Behaviorally identical to the email delivery crudauth shipped before delivery
    was pluggable; the subject/body/link building lives here now.
    """

    sends_email = True

    def __init__(self, config: EmailConfig):
        self._config = config

    async def deliver(self, intent: DeliveryIntent, db: AsyncSession | None) -> None:
        cfg = self._config
        if intent.kind in _EMAIL_NOTICES:
            subject, body = _EMAIL_NOTICES[intent.kind]
            await cfg.sender.send(
                to=intent.recipient,
                subject=subject,
                body=body.format(frontend_url=cfg.frontend_url),
                kind=intent.kind,
                context=EmailContext(
                    kind=intent.kind, link=None, recipient=intent.recipient, expires_in=0
                ),
            )
            return
        subject, path_attr, prefix = _EMAIL_SPECS[intent.kind]
        assert intent.token is not None
        link = cfg.link(getattr(cfg, path_attr), intent.token)
        await cfg.sender.send(
            to=intent.recipient,
            subject=subject,
            body=f"{prefix} {link}",
            kind=intent.kind,
            context=EmailContext(
                kind=intent.kind,
                link=link,
                recipient=intent.recipient,
                expires_in=intent.expires_in,
            ),
        )

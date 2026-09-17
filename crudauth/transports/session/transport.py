"""The session transport: cookie auth with CSRF, lockout, and device management.

This is the default transport - configuring nothing gives you cookie sessions,
CSRF synchronizer-token, login lockout, secure cookies, and ``/login`` ``/logout``.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from ...constants import (
    DEFAULT_CLEANUP_INTERVAL_MINUTES,
    DEFAULT_MAX_SESSIONS_PER_USER,
    DEFAULT_REMEMBER_ME_DAYS,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    SECONDS_PER_MINUTE,
)
from ...core import AuthContext, AuthRuntime, CookieConfig, Transport
from ...exceptions import CSRFException, ForbiddenException
from ...hooks import HookContext
from ...principal import Principal
from ...ratelimit.config import LockoutConfig, LoginSuccessClears
from ...storage import get_session_storage
from ...storage.backends.redis import redis_client_from_url
from ...storage.constants import BACKEND_MEMORY, BACKEND_REDIS
from ...utils import get_client_ip, is_cross_site
from .constants import (
    CSRF_HEADER_NAME,
    CSRF_STORAGE_PREFIX,
    REMEMBER_ME_META_KEY,
    SAFE_METHODS,
    SESSION_STORAGE_PREFIX,
)
from .manager import SessionManager

__all__ = ["SessionTransport"]


class SessionTransport(Transport):
    """Cookie-based session auth - the default transport.

    Configuring nothing gives cookie sessions, CSRF synchronizer-token (header-only),
    login lockout, secure cookies, and ``/login`` ``/logout``. CSRF is enforced
    inside [authenticate][crudauth.core.Transport.authenticate] on unsafe methods; the session cookie is never
    ``SameSite=None`` (rejected at construction).

    Args:
        backend: Where sessions and CSRF tokens live, ``"memory"`` or ``"redis"``. Left
            unset, it's Redis when this transport or [CRUDAuth][crudauth.crud_auth.CRUDAuth]
            has a ``redis_url`` or ``redis_client``, and memory otherwise.
        redis_url: Redis URL for this transport's sessions and CSRF tokens, overriding
            ``CRUDAuth``'s. The transport opens one client for it and closes it on shutdown.
        redis_client: Existing async Redis client for this transport, overriding
            ``CRUDAuth``'s. The caller owns it, so ``auth.shutdown()`` doesn't close it.
            Mutually exclusive with ``redis_url``.
        csrf: Enforce the synchronizer-token header on unsafe methods (default ``True``).
        cookies: Per-transport [CookieConfig][crudauth.core.CookieConfig] override.
        login_max_attempts: The login lockout's ``max_attempts``.
        login_attempt_window_seconds: The login lockout's ``attempt_window_seconds``.
        login_lockout_base_seconds: The login lockout's ``lockout_base_seconds``.
        login_lockout_max_seconds: The login lockout's ``lockout_max_seconds``.
        on_login_success: The login lockout's ``on_login_success``. These ``login_*``
            arguments tune the lockout shared by ``/login`` and ``/token``; any left
            unset keeps the [LockoutConfig][crudauth.ratelimit.config.LockoutConfig]
            default. ``CRUDAuth(lockout=LockoutConfig(...))`` sets the same values
            without needing a session transport; setting both raises ``ValueError``.
        management_routes: When ``True``, mount the opt-in session/CSRF management
            routes on the shared router: ``POST /logout-all``, ``GET /sessions``,
            ``DELETE /sessions/{id}``, and ``POST /csrf/refresh``. Default ``False``
            (adding routes is a choice, and a device list isn't universally wanted).

    Example:
        ```python
        CRUDAuth(
            session=get_session, user_model=User, SECRET_KEY=...,
            redis_url=...,
            transports=[SessionTransport(session_timeout_minutes=30, csrf=True)],
        )
        ```
    """

    name = "session"

    def __init__(
        self,
        *,
        backend: str | None = None,
        redis_url: str | None = None,
        redis_client: Any = None,
        csrf: bool = True,
        max_sessions_per_user: int = DEFAULT_MAX_SESSIONS_PER_USER,
        session_timeout_minutes: int = DEFAULT_SESSION_TIMEOUT_MINUTES,
        remember_me_days: int = DEFAULT_REMEMBER_ME_DAYS,
        cleanup_interval_minutes: int = DEFAULT_CLEANUP_INTERVAL_MINUTES,
        cookies: CookieConfig | None = None,
        login_max_attempts: int | None = None,
        login_attempt_window_seconds: int | None = None,
        login_lockout_base_seconds: int | None = None,
        login_lockout_max_seconds: int | None = None,
        on_login_success: LoginSuccessClears | None = None,
        management_routes: bool = False,
    ):
        if redis_url is not None and redis_client is not None:
            raise ValueError("redis_url and redis_client are mutually exclusive")
        backend = backend.lower() if backend else None
        if backend == BACKEND_MEMORY and (redis_url is not None or redis_client is not None):
            raise ValueError("backend='memory' can't be combined with redis_url or redis_client")
        self._backend = backend
        self._redis_url = redis_url
        self._redis_client = redis_client
        self.backend = backend
        self.redis_url = redis_url
        self.redis_client = redis_client
        self._owned_client: Any = None
        self.csrf_enabled = csrf
        self.max_sessions_per_user = max_sessions_per_user
        self.session_timeout_minutes = session_timeout_minutes
        self.remember_me_days = remember_me_days
        self.cleanup_interval_minutes = cleanup_interval_minutes
        self._cookie_override = cookies
        lockout_overrides: dict[str, Any] = {
            "max_attempts": login_max_attempts,
            "attempt_window_seconds": login_attempt_window_seconds,
            "lockout_base_seconds": login_lockout_base_seconds,
            "lockout_max_seconds": login_lockout_max_seconds,
            "on_login_success": on_login_success,
        }
        overrides = {name: value for name, value in lockout_overrides.items() if value is not None}
        self.lockout: LockoutConfig | None = LockoutConfig(**overrides) if overrides else None
        self.management_routes = management_routes
        self.manager: SessionManager | None = None

    # --- wiring --------------------------------------------------------------
    def bind(self, runtime: AuthRuntime) -> None:
        """Build the [SessionManager][crudauth.transports.session.manager.SessionManager] from the bound runtime.

        Note:
            Rejects ``SameSite=None`` for the session cookie at config time.
            SameSite is the backstop the header-only CSRF check leans on (the
            cookie auto-rides cross-origin, the header doesn't); ``none`` removes
            it and silently weakens CSRF. Bearer cookies *may* be ``none`` (no
            CSRF surface), so this guard is session-transport-specific.

        Note:
            Login lockout is the shared ``runtime.lockout`` (the same policy the
            bearer ``/token`` route uses), so the two endpoints can't sidestep
            each other's counter.
        """
        super().bind(runtime)
        cookies = self.cookie_config()
        if cookies.samesite == "none":
            raise ValueError(
                "SessionTransport cookies cannot use SameSite=None (it weakens CSRF "
                "protection). Use 'lax' or 'strict'."
            )
        timeout_seconds = self.session_timeout_minutes * SECONDS_PER_MINUTE
        client = self._redis_client
        if client is None and self._redis_url is not None:
            client = self._owned_client = redis_client_from_url(self._redis_url)
        elif client is None and self._backend != BACKEND_MEMORY:
            client = runtime.redis_client
        backend = self._backend or (BACKEND_REDIS if client is not None else BACKEND_MEMORY)
        if backend == BACKEND_REDIS and client is None:
            client = self._owned_client = redis_client_from_url()
        self.backend, self.redis_client = backend, client
        session_storage = get_session_storage(
            self.backend,
            prefix=SESSION_STORAGE_PREFIX,
            expiration=timeout_seconds,
            client=self.redis_client,
        )
        csrf_storage = None
        if self.csrf_enabled:
            csrf_storage = get_session_storage(
                self.backend,
                prefix=CSRF_STORAGE_PREFIX,
                expiration=timeout_seconds,
                client=self.redis_client,
            )

        self.manager = SessionManager(
            session_storage,
            csrf_storage=csrf_storage,
            max_sessions_per_user=self.max_sessions_per_user,
            session_timeout_minutes=self.session_timeout_minutes,
            remember_me_days=self.remember_me_days,
            cleanup_interval_minutes=self.cleanup_interval_minutes,
            lockout=runtime.lockout,
            cookie_secure=cookies.secure,
            cookie_samesite=cookies.samesite,
            cookie_path=cookies.path,
            trusted_proxy_hops=runtime.trusted_proxy_hops,
        )

    async def initialize(self) -> None:
        """Open the session manager's storage connections."""
        if self.manager is not None:
            await self.manager.initialize()

    async def shutdown(self) -> None:
        """Close the session manager's storage connections, and the client built from ``redis_url``."""
        if self.manager is not None:
            await self.manager.shutdown()
        if self._owned_client is not None:
            await self._owned_client.aclose()

    # --- authn ---------------------------------------------------------------
    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        """Authenticate via the session cookie.

        Returns ``None`` when no session cookie is present or the session is
        invalid/idle-expired (try the next transport). On a present, valid
        session it enforces CSRF for unsafe methods (raising on failure) and
        returns the [Principal][crudauth.principal.Principal]. A session bound to
        a ``token_version`` the user has since moved past (a password reset or
        change) also returns ``None``.
        """
        assert self.manager is not None
        session_id = request.cookies.get(self.manager.session_cookie_name)
        if not session_id:
            return None

        session = await self.manager.validate_session(
            session_id, update_activity=ctx.update_activity
        )
        if session is None:
            return None

        if ctx.enforce_csrf:
            await self._enforce_csrf(request, session_id)

        user = await ctx.resolve_user(session.user_id)
        if user is None or not ctx.repo.is_active(user):
            return None
        if session.token_version not in (None, ctx.repo.token_version(user)):
            return None
        return ctx.build_principal(
            user_id=ctx.repo.user_id(user),
            user=user,
            transport=self.name,
            scopes=(),
            metadata={"session_id": session_id},
        )

    async def revalidate(self, request: Request, principal: Principal, ctx: AuthContext) -> bool:
        """Slide the session and enforce CSRF when an earlier resolution in this request skipped them."""
        assert self.manager is not None
        session_id = principal.metadata.get("session_id")
        if not session_id:
            return True
        if ctx.update_activity and await self.manager.validate_session(session_id) is None:
            return False
        if ctx.enforce_csrf:
            await self._enforce_csrf(request, session_id)
        return True

    async def _enforce_csrf(self, request: Request, session_id: str) -> None:
        """Require a valid synchronizer-token header on unsafe methods.

        Note:
            Header-only by design: the ``csrf_token`` cookie auto-rides
            cross-origin requests but a custom header does not, so requiring the
            header (not just the cookie) is what makes the synchronizer-token check
            load-bearing. Safe methods (GET/HEAD/OPTIONS) are exempt.
        """
        if not self.csrf_enabled or request.method in SAFE_METHODS:
            return
        assert self.manager is not None
        header = request.headers.get(CSRF_HEADER_NAME)
        if not header:
            raise CSRFException("Missing CSRF token")
        if not await self.manager.validate_csrf_token(session_id, header):
            raise CSRFException("Invalid CSRF token")

    def clear_cookies(self, response: Response) -> None:
        """Expire the session and CSRF cookies."""
        assert self.manager is not None
        self.manager.clear_session_cookies(response)

    # --- routes --------------------------------------------------------------
    def contributes_routes(self) -> APIRouter:
        router = APIRouter(tags=["auth"])
        runtime = self.runtime
        db_dep = runtime.db_dependency

        @router.post("/login")
        async def login(
            request: Request,
            response: Response,
            form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
            db: Annotated[Any, Depends(db_dep)],
            remember_me: Annotated[bool, Form()] = False,
        ):
            """Log in with username/email + password; sets the session + CSRF cookies.

            Subject to login lockout (shared with bearer ``/token``). ``remember_me``
            switches the cookie from session-scoped to a long persistent lifetime.
            A request the browser marks ``Sec-Fetch-Site: cross-site`` gets a 403,
            so another site can't sign the visitor into an account it controls.

            Note:
                A disabled account returns the same "Incorrect username or
                password" as bad credentials, so a credential holder can't tell a
                disabled account from a wrong password; the real reason is logged
                server-side (``reason=disabled``) for operators.
            """
            assert self.manager is not None
            if is_cross_site(request):
                raise ForbiddenException("Cross-site login requests are not allowed.")
            ip = get_client_ip(request, runtime.trusted_proxy_hops)
            user = await runtime.authenticate_password(
                db, form_data.username, form_data.password, request=request
            )

            metadata = {REMEMBER_ME_META_KEY: True} if remember_me else {}
            session_id, csrf = await self.manager.create_session(
                request,
                user_id=runtime.repo.user_id(user),
                metadata=metadata,
                token_version=runtime.repo.token_version(user),
            )
            cookie_max_age = self.manager.timeout_seconds_for(metadata) if remember_me else None
            self.manager.set_session_cookies(response, session_id, csrf, max_age=cookie_max_age)

            await runtime.hooks.run_after_login(
                runtime.repo.to_dict(user),
                request=request,
                context=HookContext(
                    ip_address=ip,
                    user_agent=request.headers.get("user-agent"),
                    transport=self.name,
                    request=request,
                ),
            )
            return {
                "id": runtime.repo.user_id(user),
                "username": runtime.repo.get(user, "username"),
                "csrf_token": csrf,
            }

        @router.post("/logout")
        async def logout(request: Request, response: Response, db: Annotated[Any, Depends(db_dep)]):
            """Revoke the current session and clear the auth cookies (CSRF-protected).

            Clears every configured transport's cookies, including a bearer refresh
            cookie. A session that already expired has nothing left to protect, so
            its cookies are cleared without a CSRF check.
            """
            assert self.manager is not None
            session_id = request.cookies.get(self.manager.session_cookie_name)
            session = (
                await self.manager.validate_session(session_id, update_activity=False)
                if session_id
                else None
            )
            user_dict = None
            if session_id and session is not None:
                await self._enforce_csrf(request, session_id)
                user = await runtime.repo.get_by_id(db, session.user_id)
                if user is not None:
                    user_dict = runtime.repo.to_dict(user)
                await self.manager.terminate_session(session_id, reason="logout")
            runtime.clear_cookies(response)
            if user_dict is not None:
                await runtime.hooks.run_after_logout(
                    user_dict,
                    request=request,
                    context=HookContext(transport=self.name, request=request),
                )
            return {"detail": "Logged out"}

        return router

"""``CRUDAuth`` - the one object you configure and mount.

```python
auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="...")
app.include_router(auth.router)

@app.get("/me")
async def me(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```
"""

import inspect
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Callable, Literal, Sequence, cast

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, create_model

from .register import build_register_route
from .constants import (
    DEFAULT_ALGORITHM,
    DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
    DEFAULT_LOGIN_MAX_ATTEMPTS,
    OAUTH_STATE_TTL_SECONDS,
    USED_TOKEN_TTL_SECONDS,
)
from .core import AuthRuntime, CookieConfig, Transport
from .email.channel import DeliveryChannel
from .email.router import build_email_router
from .email.service import EmailFlowService
from .exceptions import (
    BadRequestException,
    ForbiddenException,
    NotFoundException,
    RateLimitException,
    UnauthorizedException,
)
from .hooks import AuthHooks, HookContext
from .identity import IdentityConfig
from .oauth import OAuthAccountService, OAuthProviderFactory
from .oauth.router import build_oauth_router
from .principal import Principal
from .password import PasswordContext, PasswordPolicy, PasswordSource
from .provisioning import NewUserFields
from .ratelimit import (
    DEFAULT_RATE_LIMITS,
    KeyBy,
    LockoutPolicy,
    MemoryRateLimiterBackend,
    RateLimit,
    RateLimitResolver,
    redis_rate_limiter,
)
from .ratelimit.constants import RATE_LIMIT_NAMESPACE
from .repository import REGISTRATION_ALLOWED_FIELDS, UserRepository
from .resolution import PrincipalResolver
from .storage import MemorySessionStorage, get_session_storage
from .storage.backends.redis import redis_client_from_url
from .sudo import SudoConfig, SudoManager
from .storage.constants import BACKEND_MEMORY, BACKEND_REDIS
from .transports.bearer.transport import BearerTransport
from .transports.session.constants import REMEMBER_ME_META_KEY
from .transports.session.transport import SessionTransport
from .utils import (
    get_client_ip,
    get_password_hash,
    is_unusable_password,
    takes_two_arguments,
    verify_password,
)

if TYPE_CHECKING:  # pragma: no cover
    from .ratelimit import RateLimiterBackend
    from .storage.base import AbstractSessionStorage

logger = logging.getLogger("crudauth")

__all__ = ["CRUDAuth"]


class _SetPasswordIn(BaseModel):
    new_password: str


class _ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class SessionInfo(BaseModel):
    """One active session, as returned by ``GET /sessions`` (the opt-in management route).

    ``device`` is the parsed user-agent info (browser/os/device flags), empty when
    UA parsing isn't available; timestamps serialize to ISO-8601.

    Example:
        ```python
        # each entry in the GET /sessions response:
        SessionInfo(
            session_id="9f3c...",
            device={"browser": "Chrome", "os": "macOS", "is_mobile": False},
            ip="203.0.113.7",
            created_at=created, last_activity=seen, current=True,
        )
        ```
    """

    session_id: str
    device: dict[str, Any] = Field(default_factory=dict)
    ip: str = ""
    created_at: datetime
    last_activity: datetime
    current: bool = False


class CRUDAuth:
    """Composition root: configure transports, mount routers, gate routes.

    Construct one per auth surface. It owns the user repository, the shared
    [AuthRuntime][crudauth.core.AuthRuntime], the rate-limiter backend, and the
    assembled routers. Session auth is the default; add bearer/oauth/email by
    passing ``transports=``, ``oauth=``, ``email=``.

    Example:
        ```python
        auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")
        app.include_router(auth.router)

        @app.get("/me")
        async def me(user: Principal = Depends(auth.current_user())):
            return {"id": user.user_id}
        ```
    """

    def __init__(
        self,
        *,
        session: Callable[..., Any],
        user_model: type[Any],
        SECRET_KEY: str,
        transports: Sequence[Transport] | None = None,
        column_map: dict[str, str] | None = None,
        identity: IdentityConfig | None = None,
        oauth: dict[str, Any] | None = None,
        oauth_paths: dict[str, str] | None = None,
        oauth_response_mode: Literal["redirect", "json"] = "redirect",
        email: Any = None,
        channels: list[DeliveryChannel] | None = None,
        hooks: AuthHooks | None = None,
        redirect_base_url: str | None = None,
        algorithm: str = DEFAULT_ALGORITHM,
        cookies: CookieConfig | None = None,
        register_schema: type[BaseModel] | None = None,
        register_extra_fields: set[str] | None = None,
        new_user_fields: NewUserFields | None = None,
        new_user_defaults: dict[str, Any] | None = None,
        rate_limiter: "RateLimiterBackend | None" = None,
        redis_url: str | None = None,
        redis_client: Any = None,
        rate_limits: dict[str, RateLimit] | None = None,
        trusted_proxy_hops: int = 0,
        sudo: SudoConfig | None = None,
        warn_on_memory_backend: bool = True,
        password_policy: PasswordPolicy | None = None,
    ):
        """Configure the auth surface.

        Args:
            session: FastAPI dependency that yields an ``AsyncSession`` (your
                ``get_session``); every route and the ``current_user`` dependency
                acquire the DB through it.
            user_model: Your SQLAlchemy user model (typically inheriting
                [AuthUserMixin][crudauth.models.mixin.AuthUserMixin]).
            SECRET_KEY: Secret used to sign session/JWT and email tokens.
            transports: Ordered auth channels to enable; defaults to a single
                [SessionTransport][crudauth.transports.session.transport.SessionTransport]. Order is the first-wins precedence.
            column_map: Maps crudauth logical field names to your model's actual
                column names when they differ (e.g. ``{"hashed_password": "pw_hash"}``).
            oauth: ``{provider_name: OAuthCredentials}`` to enable OAuth login;
                requires ``redirect_base_url`` and a session transport.
            oauth_paths: Optional OAuth router paths: ``prefix``,
                ``authorize_path``, and ``callback_path``. Defaults to
                ``{"prefix": "/oauth", "authorize_path": "/{provider}/authorize",
                "callback_path": "/{provider}/callback"}``. Both paths must contain
                ``{provider}``. The provider redirect URI is ``redirect_base_url``
                plus ``prefix`` plus the callback path, so ``redirect_base_url``
                must include any prefix the app adds when mounting the router.
            oauth_response_mode: ``"redirect"`` (default) or ``"json"``. In JSON
                mode ``authorize`` returns ``{"url": ...}`` and ``callback``
                returns ``{"user": ..., "csrf_token": ..., "redirect_to": ...}``
                with the session cookies set, or a ``400`` on failure.
            email: An [EmailConfig][crudauth.email.config.EmailConfig] to enable
                verify/reset/change flows over email (the built-in delivery
                channel); ``None`` disables email delivery. Either ``email`` or
                ``channels`` enables the recovery endpoints.
            channels: Additional [DeliveryChannel][crudauth.email.channel.DeliveryChannel]s
                to route recovery tokens over (SMS, WhatsApp, push, ...). Fired
                alongside the email channel if ``email`` is also set, every channel
                best-effort. With ``channels`` and no ``email``, the recovery
                endpoints still mount (token lifetimes fall back to the defaults).
            hooks: Lifecycle callbacks ([AuthHooks][crudauth.hooks.AuthHooks]).
            redirect_base_url: Public base URL used to build OAuth redirect URIs
                and the post-login redirect default.
            algorithm: JWT signing algorithm (default ``"HS256"``).
            cookies: App-wide [CookieConfig][crudauth.core.CookieConfig] (``secure`` /
                ``samesite`` / ``path``); transports may override per-instance.
            register_schema: Custom Pydantic body for ``/register``. By default
                only ``email``/``username`` are persisted; any other field is
                dropped unless its name is listed in ``register_extra_fields``.
            register_extra_fields: App-defined model columns that ``/register``
                is allowed to set (e.g. ``{"full_name", "locale"}``). Registration
                is an allowlist: without opting a column in here it is dropped,
                so adding a column to your model never silently becomes settable
                at signup. crudauth's privileged fields (``is_superuser``,
                ``email_verified``, ...) can never be opted in.
            new_user_defaults: Constant app columns to set on every new user, on
                BOTH ``/register`` and OAuth signup (e.g. ``{"tier_id": FREE}``).
                The declarative shortcut for fixed values; gated like
                ``new_user_fields`` (a crudauth-owned key is dropped + warned at
                construction).
            new_user_fields: Callback (sync or async) returning extra columns to
                set when crudauth creates a user, for values that must be
                *derived* (and may read the DB) rather than constant - e.g.
                ``lambda ctx: {"name": ctx.suggested_name}``. Receives a trusted
                [NewUserContext][crudauth.provisioning.NewUserContext] (never the
                request body) and returns app columns only, as a ``dict`` or a
                ``BaseModel``; any crudauth logical field it returns is dropped
                (crudauth stays authoritative). Merged into the single insert
                after ``new_user_defaults``, so a derived value can override a
                constant default. Client-typed fields belong in ``register_schema``
                /``register_extra_fields``, not here.
            rate_limiter: Backend for lockout/throttles; defaults to an in-process
                [MemoryRateLimiterBackend][crudauth.ratelimit.backends.memory.MemoryRateLimiterBackend]. Use
                ``redis_rate_limiter(...)`` in production.
            redis_url: Redis URL for every server-side store: sessions and CSRF
                tokens, the one-time-token and OAuth-state stores, and the default
                rate limiter. A part configured directly (a ``SessionTransport``
                with its own ``backend``/``redis_url``/``redis_client``, or
                ``rate_limiter=``) keeps its own setting. Mutually exclusive with
                ``redis_client``.
            redis_client: An existing async Redis client to use the same way as
                ``redis_url``, with either ``decode_responses`` setting. The caller
                owns it, so ``shutdown()`` doesn't close it. Mutually exclusive with
                ``redis_url``.
            rate_limits: Per-action overrides merged over
                :data:`~crudauth.ratelimit.DEFAULT_RATE_LIMITS`.
            trusted_proxy_hops: Number of trusted reverse proxies in front of the
                app. ``0`` (default) ignores ``X-Forwarded-For`` and keys per-IP
                rate limits / lockout on the socket peer; set to the count of
                proxies you control (e.g. ``1`` behind a single nginx/Caddy) so
                the real client IP is read without trusting attacker-supplied
                header values. See [get_client_ip][crudauth.utils.get_client_ip].
            sudo: Enable sudo mode (short-lived re-authentication for sensitive
                actions) with this [SudoConfig][crudauth.sudo.SudoConfig]. Requires
                a session transport - elevation is stamped on the server-side
                session. Exposes ``auth.sudo`` and ``auth.require_sudo()``.
            warn_on_memory_backend: Log a startup warning when an in-memory
                backend is active (the zero-config default). In-memory state is
                per-process, so under multiple workers it silently breaks; set
                ``False`` to silence once you've accepted that (e.g. single-worker
                dev).
            password_policy: The [PasswordPolicy][crudauth.password.PasswordPolicy] every
                new password must meet on registration, set, change and reset. The
                default requires at least 8 characters.

        Raises:
            ValueError: If ``SECRET_KEY`` is empty; if ``oauth`` or ``sudo`` is
                set without a session transport (and ``oauth`` also needs
                ``redirect_base_url``); or if a configured OAuth provider has no
                ``{provider}_id`` column on the user model.
        """
        if not SECRET_KEY:
            raise ValueError("SECRET_KEY is required")
        if redis_client is not None and redis_url is not None:
            raise ValueError("redis_url and redis_client are mutually exclusive")
        self.session = session
        self.password_policy = password_policy or PasswordPolicy()
        self.identity = identity or IdentityConfig()
        self.repo = UserRepository(
            user_model,
            column_map,
            register_extra_fields,
            login_fields=self.identity.login,
            recovery=self.identity.recovery,
        )
        self._validate_identity(oauth=oauth, email=email)
        self.new_user_fields = new_user_fields
        self._new_user_defaults = self.repo.filter_provisioning_data(new_user_defaults or {})
        self.hooks = hooks or AuthHooks()
        self.transports: list[Transport] = list(transports) if transports else [SessionTransport()]
        self._register_schema = register_schema
        self._warn_on_register_extra_fields(register_extra_fields)
        self._warn_on_privileged_register_fields(register_schema)
        self._rate_limits: dict[str, RateLimit] = {**DEFAULT_RATE_LIMITS, **(rate_limits or {})}
        self._owned_redis = redis_client_from_url(redis_url) if redis_url is not None else None
        shared_redis = redis_client if redis_client is not None else self._owned_redis

        self.runtime = AuthRuntime(
            secret_key=SECRET_KEY,
            repo=self.repo,
            hooks=self.hooks,
            redirect_base_url=redirect_base_url,
            db_dependency=session,
            algorithm=algorithm,
            cookie_config=cookies or CookieConfig(),
            rate_limiter=rate_limiter
            or (
                redis_rate_limiter(client=shared_redis)
                if shared_redis is not None
                else MemoryRateLimiterBackend()
            ),
            trusted_proxy_hops=trusted_proxy_hops,
            redis_client=shared_redis,
        )
        self._principals = PrincipalResolver(self.runtime)
        self._session_transport = next(
            (t for t in self.transports if isinstance(t, SessionTransport)), None
        )
        self._bearer_transport = next(
            (t for t in self.transports if isinstance(t, BearerTransport)), None
        )
        self.runtime.lockout = self._build_lockout(self._session_transport)
        for transport in self.transports:
            transport.bind(self.runtime)

        self.sudo: SudoManager | None = None
        if sudo is not None:
            self._build_sudo(sudo)

        self._email_service: EmailFlowService | None = None
        self._email_token_store: AbstractSessionStorage[Any] | None = None
        if self.identity.recovery is not None and (email is not None or channels):
            self._build_email(email, channels, algorithm)

        self._oauth_router: APIRouter | None = None
        self._oauth_service: OAuthAccountService | None = None
        self._oauth_state_storage: AbstractSessionStorage[Any] | None = None
        if oauth:
            self._build_oauth(oauth, redirect_base_url, oauth_paths, oauth_response_mode)

        if warn_on_memory_backend:
            self._warn_on_memory_backend()

    def _build_lockout(
        self, session_transport: "SessionTransport | None"
    ) -> "LockoutPolicy | None":
        """Build the one shared login-lockout policy (or ``None`` if no limiter).

        Note:
            Called before transports are bound, because both the session and
            bearer transports read ``runtime.lockout`` in their ``bind``/routes.
            Mirrors the session transport's lockout config when present, else
            uses defaults - so a bearer-only API still gets lockout.
        """
        if self.runtime.rate_limiter is None:
            return None
        st = session_transport
        return LockoutPolicy(
            self.runtime.rate_limiter,
            max_attempts=st.login_max_attempts if st else DEFAULT_LOGIN_MAX_ATTEMPTS,
            attempt_window_seconds=(
                st.login_attempt_window_seconds if st else DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS
            ),
            lockout_base_seconds=(
                st.login_lockout_base_seconds if st else DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS
            ),
            lockout_max_seconds=(
                st.login_lockout_max_seconds if st else DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS
            ),
            on_login_success=st.on_login_success if st else "clear_all",
            fail_open=False,
        )

    def _validate_identity(self, *, oauth: dict[str, Any] | None, email: Any) -> None:
        """Check the identity contract against the model, fail-closed at construction.

        The model owns the shape; this asserts the config agrees with it, so a
        login field that isn't a unique column, a non-unique recovery field, OAuth
        without an email login, or an email flow on a model with no email column
        all raise here rather than splitting into a silent second source of truth.
        """
        for login_field in self.identity.login:
            if not self.repo.is_unique_column(login_field):
                raise ValueError(
                    f"identity.login field '{login_field}' is not a unique column on the user "
                    "model; every login field must be a single-field unique column."
                )
        recovery = self.identity.recovery
        if recovery is not None and not self.repo.is_unique_column(recovery):
            raise ValueError(
                f"identity.recovery field '{recovery}' is not a unique column on the user "
                "model; the recovery field must be a single-field unique column."
            )
        if oauth and "email" not in self.identity.login:
            raise ValueError(
                "OAuth requires 'email' in identity.login - OAuth links and creates accounts "
                "by email, so an email-less contract cannot enable OAuth."
            )
        if email is not None and not self.repo.has("email"):
            raise ValueError("email=EmailConfig(...) requires an 'email' column on the user model.")

    def _warn_on_register_extra_fields(self, extra: set[str] | None) -> None:
        """Warn when ``register_extra_fields`` tries to opt in a privileged field.

        Those names stay gated regardless (the repo drops them), so this is a
        no-op for safety - but it's a developer misconfiguration worth surfacing.
        """
        if not extra:
            return
        gated = self.repo.gated_register_fields(extra)
        if gated:
            logger.warning(
                "register_extra_fields lists privileged field(s) %s; these stay gated "
                "and will NOT be settable at registration. Remove them.",
                sorted(gated),
            )

    def _warn_on_privileged_register_fields(self, schema: type[BaseModel] | None) -> None:
        """Warn when a custom register schema declares fields registration drops.

        Two cases, both surfaced at startup so a silent drop never bites:

        - **Privileged** fields (``is_superuser``, ``email_verified``, ...) are
          dropped unconditionally - declaring one is a security-relevant mistake.
        - **Real model columns** that aren't opted in via ``register_extra_fields``
          are also dropped; the developer likely expected them to persist.
        """
        if schema is None:
            return
        fields = schema.model_fields.keys()
        gated = self.repo.gated_register_fields(fields)
        if gated:
            logger.warning(
                "register_schema %s declares privileged field(s) %s that registration "
                "will ignore. /register may only set %s plus columns you opt in via "
                "register_extra_fields; remove these from the schema.",
                schema.__name__,
                sorted(gated),
                sorted(REGISTRATION_ALLOWED_FIELDS),
            )
        droppable = self.repo.droppable_register_fields(fields)
        if droppable:
            logger.warning(
                "register_schema %s declares field(s) %s that map to model columns but "
                "are not opted in; registration will drop them. Add them to "
                "register_extra_fields=%s to persist them.",
                schema.__name__,
                sorted(droppable),
                sorted(droppable),
            )

    # --- backend detection ---------------------------------------------------
    def _backend_config(self) -> tuple[str, Any]:
        if self.runtime.redis_client is not None:
            return BACKEND_REDIS, self.runtime.redis_client
        if self._session_transport is not None and self._session_transport.backend is not None:
            return self._session_transport.backend, self._session_transport.redis_client
        return BACKEND_MEMORY, None

    def _warn_on_memory_backend(self) -> None:
        """Warn when an in-memory backend is active (the zero-config default).

        In-memory state is per-process: under multiple workers it is not shared,
        so login-lockout counters, sessions/CSRF tokens, and single-use token /
        OAuth-state atomicity silently weaken. Production should use redis.
        """
        memory: list[str] = []
        if isinstance(self.runtime.rate_limiter, MemoryRateLimiterBackend):
            memory.append("rate limiter (lockout/throttle counters)")
        if any(
            isinstance(t, SessionTransport) and t.backend == BACKEND_MEMORY for t in self.transports
        ):
            memory.append("sessions/CSRF")
        stores = (self._email_token_store, self._oauth_state_storage)
        if any(isinstance(store, MemorySessionStorage) for store in stores):
            memory.append("one-time-token/OAuth-state stores")
        if not memory:
            return
        logger.warning(
            "crudauth: using in-memory backend(s) - %s. In-memory state is per-process, so "
            "under multiple workers it is NOT shared and those guarantees weaken silently. "
            "Pass redis_url= or redis_client= to CRUDAuth in production, or "
            "warn_on_memory_backend=False to silence.",
            ", ".join(memory),
        )

    # --- public: session manager --------------------------------------------
    async def validate_password(
        self,
        password: str,
        *,
        user: Any = None,
        source: PasswordSource = "set",
        field: str = "password",
    ) -> None:
        """Check ``password`` against ``password_policy`` before your own code hashes it.

        Raises [PasswordPolicyException][crudauth.exceptions.PasswordPolicyException]
        (422) at ``field`` when it fails. Pass the ``user`` it's for so validators
        taking a [PasswordContext][crudauth.password.PasswordContext] see its username
        and email.
        """
        if user is None:
            context = PasswordContext(source=source)
        else:
            context = PasswordContext.for_user(self.repo, source, user)
        await self.password_policy.enforce(password, context, field=field)

    @property
    def sessions(self):
        """The [SessionManager][crudauth.transports.session.manager.SessionManager] of the configured session transport."""
        if self._session_transport is None or self._session_transport.manager is None:
            raise RuntimeError(
                "Session management requires a SessionTransport in transports=[...]."
            )
        return self._session_transport.manager

    @property
    def emails(self) -> "EmailFlowService | None":
        """The [EmailFlowService][crudauth.email.service.EmailFlowService], or ``None`` when no recovery is configured.

        Drives the recovery flows (`request_recovery_verification`, `reset_password`,
        `request_email_change`, ...) so a hand-written route can trigger them with
        the same token mint/verify the built-in endpoints use.

        Example:
            ```python
            if auth.emails is not None:
                await auth.emails.request_password_reset(db, email)
            ```
        """
        return self._email_service

    @property
    def oauth(self) -> "OAuthAccountService | None":
        """The [OAuthAccountService][crudauth.oauth.OAuthAccountService], or ``None`` when OAuth isn't configured.

        Exposes `get_or_create_user` (provider-id → verified-email link → create) so
        a hand-written OAuth callback can reuse the linking/creation rules.

        Example:
            ```python
            if auth.oauth is not None:
                user, created = await auth.oauth.get_or_create_user(info, db)
            ```
        """
        return self._oauth_service

    @property
    def oauth_router(self) -> APIRouter:
        """The configured OAuth routes, for apps keeping their own auth routes."""
        if self._oauth_router is None:
            raise RuntimeError("OAuth is not configured")
        return self._oauth_router

    # --- email wiring --------------------------------------------------------
    def _build_email(
        self, email: Any, channels: list[DeliveryChannel] | None, algorithm: str
    ) -> None:
        backend, redis_client = self._backend_config()
        token_store = get_session_storage(
            backend, prefix="used_token:", expiration=USED_TOKEN_TTL_SECONDS, client=redis_client
        )
        self._email_token_store = token_store
        self._email_service = EmailFlowService(
            repo=self.repo,
            secret_key=self.runtime.secret_key,
            config=email,
            channels=channels,
            hooks=self.hooks,
            algorithm=algorithm,
            token_store=token_store,
            session_manager=self.sessions if self._session_transport else None,
            rate_limiter=self.runtime.rate_limiter,
            rate_limits=self._rate_limits,
            password_policy=self.password_policy,
        )
        self.runtime.email_service = self._email_service

    # --- oauth wiring --------------------------------------------------------
    def _build_oauth(
        self,
        oauth: dict[str, Any],
        redirect_base_url: str | None,
        oauth_paths: dict[str, str] | None = None,
        oauth_response_mode: Literal["redirect", "json"] = "redirect",
    ) -> None:
        if self._session_transport is None:
            raise ValueError(
                "OAuth establishes a session on callback; add a SessionTransport to transports=[...]."
            )
        if not redirect_base_url:
            raise ValueError("redirect_base_url is required when oauth=... is configured")

        default_paths = {
            "prefix": "/oauth",
            "authorize_path": "/{provider}/authorize",
            "callback_path": "/{provider}/callback",
        }
        unknown_paths = sorted(set(oauth_paths or {}) - set(default_paths))
        if unknown_paths:
            raise ValueError(
                f"Unknown oauth_paths key(s) {unknown_paths}; expected {sorted(default_paths)}."
            )
        paths = {**default_paths, **(oauth_paths or {})}
        providers = {}
        for name, creds in oauth.items():
            if not self.repo.has(f"{name}_id"):
                raise ValueError(
                    f"OAuth provider {name!r} needs a '{name}_id' column on the user model "
                    f"to store and match its account id. Add it (e.g. "
                    f"'{name}_id: Mapped[str | None] = mapped_column(unique=True, index=True, "
                    f"default=None)') or map it via column_map=."
                )
            callback_route = paths["callback_path"].replace("{provider}", name)
            route = "/".join(
                part.strip("/") for part in (paths["prefix"], callback_route) if part.strip("/")
            )
            redirect_uri = f"{redirect_base_url.rstrip('/')}/{route}"
            providers[name] = OAuthProviderFactory.create_provider(
                name,
                client_id=creds.client_id,
                client_secret=creds.client_secret,
                redirect_uri=redirect_uri,
                scopes=creds.scopes,
            )

        backend, redis_client = self._backend_config()
        state_storage = get_session_storage(
            backend, prefix="oauth_state:", expiration=OAUTH_STATE_TTL_SECONDS, client=redis_client
        )
        self._oauth_state_storage = state_storage
        self._oauth_service = OAuthAccountService(
            self.repo, self.new_user_fields, self._new_user_defaults
        )
        self._oauth_router = build_oauth_router(
            runtime=self.runtime,
            providers=providers,
            state_storage=state_storage,
            account_service=self._oauth_service,
            session_manager=self.sessions,
            default_redirect=redirect_base_url,
            response_mode=oauth_response_mode,
            **paths,
        )

    # --- sudo wiring ---------------------------------------------------------
    def _build_sudo(self, config: SudoConfig) -> None:
        if self._session_transport is None:
            raise ValueError(
                "Sudo stamps the elevation on a server-side session; add a "
                "SessionTransport to transports=[...]."
            )
        self.sudo = SudoManager(
            session_manager=self.sessions,
            repo=self.repo,
            backend=self.runtime.rate_limiter,
            hooks=self.hooks,
            config=config,
        )

    # --- the current_user() factory -----------------------------------------
    async def resolve_principal(
        self, request: Request, update_activity: bool = False
    ) -> Principal | None:
        """Resolve the request principal outside FastAPI dependency injection.

        This is intended for middleware and other request-level code. It tries
        transports in configured order, returns ``None`` for anonymous or
        invalid credentials, does not enforce CSRF, and does not slide sessions
        unless ``update_activity=True``. A later ``current_user()`` in the same
        request reuses the result, reloading the user through its own session.

        It opens its own DB session by calling the ``session`` dependency
        directly, so FastAPI's ``dependency_overrides`` don't apply to it.
        """
        return await self._principals.resolve_outside_dependencies(
            request, self.transports, update_activity=update_activity
        )

    async def authenticate_password(
        self, db: Any, identifier: str, password: str, *, request: Request
    ) -> Any:
        """Verify a username/email + password with the full login hardening.

        The hardened credential check behind ``/login`` and ``/token``, exposed so
        a hand-written login route gets the same protections (shared escalating
        lockout, timing-equalized verification, disabled-account check) instead of
        reassembling them. Returns the user row; raises ``RateLimitException`` on
        lockout and ``UnauthorizedException`` on bad credentials. Delegates to
        [AuthRuntime.authenticate_password][crudauth.core.AuthRuntime.authenticate_password].

        Example:
            ```python
            @app.post("/my-login")
            async def my_login(request: Request, form: MyForm, db=Depends(get_db)):
                user = await auth.authenticate_password(
                    db, form.username, form.password, request=request
                )
                sid, csrf = await auth.sessions.create_session(request, auth.repo.user_id(user))
                ...
            ```
        """
        return await self.runtime.authenticate_password(db, identifier, password, request=request)

    def issue_tokens(self, user: Any, *, scopes: list[str] | None = None) -> dict[str, Any]:
        """Mint a bearer access (+refresh) token pair for a user.

        The hardened issuance behind ``/token``, exposed for a hand-written token
        endpoint: ``scopes`` are clamped to the transport's ``grantable_scopes``
        (no self-grant) and both tokens carry the ``token_version`` epoch (so a
        password reset revokes them). The refresh token is returned under
        ``refresh_token`` (there's no ``Response`` to set a cookie on). Delegates to
        [BearerTransport.issue_tokens][crudauth.transports.bearer.transport.BearerTransport.issue_tokens].

        Raises:
            RuntimeError: If no [BearerTransport][crudauth.transports.bearer.transport.BearerTransport] is configured.

        Example:
            ```python
            user = await auth.authenticate_password(db, ident, pw, request=request)
            tokens = auth.issue_tokens(user, scopes=["read"])
            ```
        """
        if self._bearer_transport is None:
            raise RuntimeError("issue_tokens requires a BearerTransport")
        return self._bearer_transport.issue_tokens(user, scopes=scopes)

    def current_user(
        self,
        *,
        optional: bool = False,
        superuser: bool = False,
        verified: bool = False,
        scopes: list[str] | None = None,
        transport: str | list[str] | None = None,
        check: Callable[[Principal], Any] | None = None,
    ) -> Callable[..., Any]:
        """Build a FastAPI dependency that authenticates and authorizes a request.

        Every gate is a keyword: ``optional``, ``superuser``, ``verified``,
        ``scopes``, ``transport`` (narrow to one/some transports), and ``check``.

        Note:
            ``check`` is a predicate (sync or async) run last on the resolved
            principal. Returning ``False`` denies the request with 403. To deny
            with a custom status/message, raise your own exception from inside
            ``check``. Returning ``None`` (or anything that isn't ``False``)
            allows - so both styles work: a boolean predicate
            (``check=lambda p: p.is_superuser``) and a raise-to-deny callback that
            simply returns nothing on success.

        Note:
            Transports are tried in order, first credential wins. A transport
            returns ``None`` when its credential is *absent* (move to the next),
            but RAISES for a *present-but-invalid* one (e.g. a session cookie that
            fails the CSRF header check on a mutation). That hard-fail propagates
            even under ``optional=True`` - a tampered credential is an attack
            signal, not "treat me as anonymous".

        Returns:
            An async dependency yielding the [Principal][crudauth.principal.Principal] (or ``None`` when
            ``optional`` and no credential is present).

        Example:
            ```python
            @app.get("/admin")
            async def admin(_: Principal = Depends(auth.current_user(superuser=True))):
                ...
            ```
        """
        if verified and self.identity.recovery is None:
            raise ValueError(
                "current_user(verified=True) requires a recovery factor (identity.recovery); "
                "an account shape with no recovery has nothing to prove control of."
            )
        selected = self._select_transports(transport)
        required_scopes = list(scopes or [])

        async def dependency(
            request: Request, db: Annotated[Any, Depends(self.session)]
        ) -> Principal | None:
            principal = await self._principals.resolve(request, db, selected)

            if principal is None:
                if optional:
                    return None
                raise UnauthorizedException("Not authenticated")

            if superuser and not principal.is_superuser:
                raise ForbiddenException("Insufficient privileges")
            if verified and not principal.recovery_verified:
                raise ForbiddenException("Recovery factor not verified")
            if required_scopes and not principal.has_scopes(required_scopes):
                raise ForbiddenException("Insufficient scope")
            if check is not None:
                result = check(principal)
                if inspect.isawaitable(result):
                    result = await result
                if result is False:
                    raise ForbiddenException("Access denied")
            return principal

        return dependency

    def require_sudo(self) -> Callable[..., Any]:
        """Build a dependency that requires a current sudo elevation.

        Authenticates like [current_user][crudauth.crud_auth.CRUDAuth.current_user]
        (reusing the per-request principal cache) and then demands an unexpired
        sudo stamp, raising 403 otherwise. Compose it with ``current_user`` gates
        on the same route to also enforce identity/role:

        Example:
            ```python
            @app.post("/account/close")
            async def close(
                user: Principal = Depends(auth.current_user(superuser=True)),
                _: Principal = Depends(auth.require_sudo()),
            ):
                ...
            ```

        Raises:
            RuntimeError: If sudo isn't configured (pass ``sudo=SudoConfig()``).
        """
        if self.sudo is None:
            raise RuntimeError("Sudo is not configured; pass sudo=SudoConfig() to CRUDAuth.")
        sudo = self.sudo
        user_dep = self.current_user()

        async def dependency(principal: Annotated[Principal, Depends(user_dep)]) -> Principal:
            if not await sudo.is_elevated(principal):
                raise ForbiddenException("Re-authentication required.")
            return principal

        return dependency

    def _select_transports(self, transport: str | list[str] | None) -> list[Transport]:
        if transport is None:
            return self.transports
        names = [transport] if isinstance(transport, str) else list(transport)
        selected = [t for t in self.transports if t.name in names]
        if not selected:
            raise ValueError(
                f"No configured transport matches {names!r}; "
                f"configured: {[t.name for t in self.transports]}"
            )
        return selected

    # --- the rate_limit() factory -------------------------------------------
    def rate_limit(
        self,
        action: str,
        limit: RateLimit | RateLimitResolver | None = None,
        *,
        key: "KeyBy | Callable[..., str]" = KeyBy.IP,
        transport: str | list[str] | None = None,
    ) -> Callable[..., Any]:
        """Build a FastAPI dependency that throttles an endpoint.

        ``limit`` is a ``RateLimit`` or a sync/async function of ``(request, principal)``
        returning one (``None`` for no limit). Without it, the ``rate_limits=`` override
        or :data:`~crudauth.ratelimit.DEFAULT_RATE_LIMITS` entry for ``action`` applies.
        ``key`` picks who shares a budget: a ``KeyBy`` member, ``key(request)``, or
        ``key(request, principal)``. ``transport`` narrows which credentials identify the
        caller, as on [current_user][crudauth.crud_auth.CRUDAuth.current_user]. Writes
        ``X-RateLimit-*`` headers and raises
        [RateLimitException][crudauth.exceptions.RateLimitException] (429) when the caller exceeds the window.

        Example:
            ```python
            @app.post("/contact", dependencies=[Depends(auth.rate_limit("contact", RateLimit(5, 60)))])
            async def contact(...): ...
            ```
        """
        resolved = limit or self._rate_limits.get(action) or DEFAULT_RATE_LIMITS.get(action)
        if resolved is None:
            raise ValueError(
                f"No rate limit configured for action {action!r}; pass limit=RateLimit(...)."
            )
        selected = self._select_transports(transport)

        if key is KeyBy.USER:
            user_dep = self.current_user(transport=transport)

            async def by_user(
                request: Request,
                response: Response,
                principal: Annotated[Principal, Depends(user_dep)],
            ) -> None:
                ident = str(principal.user_id)
                await self._apply_rate_limit(request, response, action, ident, resolved, principal)

            return by_user

        trusted_hops = self.runtime.trusted_proxy_hops
        needs_principal = callable(resolved)

        if key is KeyBy.IP:

            def ident_for(request: Request, principal: Principal | None) -> str:
                return get_client_ip(request, trusted_hops)

        elif key is KeyBy.USER_OR_IP:
            needs_principal = True

            def ident_for(request: Request, principal: Principal | None) -> str:
                if principal is not None:
                    return f"user:{principal.user_id}"
                return f"ip:{get_client_ip(request, trusted_hops)}"

        elif callable(key):
            key_callback = key
            takes_principal = takes_two_arguments(key_callback)
            needs_principal = needs_principal or takes_principal

            def ident_for(request: Request, principal: Principal | None) -> str:
                if takes_principal:
                    return key_callback(request, principal)
                return key_callback(request)

        else:
            raise ValueError(f"Unsupported rate limit key: {key!r}")

        if not needs_principal:

            async def without_principal(request: Request, response: Response) -> None:
                ident = ident_for(request, None)
                await self._apply_rate_limit(request, response, action, ident, resolved, None)

            return without_principal

        async def with_principal(
            request: Request, response: Response, db: Annotated[Any, Depends(self.session)]
        ) -> None:
            principal = await self._principals.resolve(request, db, selected, enforce_csrf=False)
            ident = ident_for(request, principal)
            await self._apply_rate_limit(request, response, action, ident, resolved, principal)

        return with_principal

    async def _apply_rate_limit(
        self,
        request: Request,
        response: Response,
        action: str,
        ident: str,
        limit: RateLimit | RateLimitResolver,
        principal: Principal | None,
    ) -> None:
        """Run the window check, set ``X-RateLimit-*`` headers, raise 429 if over.

        Note:
            Headers set on the injected ``Response`` are dropped when the
            dependency raises, so the limit headers are also attached to the
            ``RateLimitException`` on the over-limit path.
        """
        effective: RateLimit | None
        if callable(limit):
            result = limit(request, principal)
            if inspect.isawaitable(result):
                result = await result
            effective = result
        else:
            effective = limit
        if effective is None:
            return
        backend = self.runtime.rate_limiter
        if backend is None or effective.disabled:
            return
        count, limited, retry_after = await backend.increment_and_check(
            f"{RATE_LIMIT_NAMESPACE}:{action}:{ident}",
            effective.times,
            effective.seconds,
            fail_open=True,
        )
        response.headers["X-RateLimit-Limit"] = str(effective.times)
        response.headers["X-RateLimit-Remaining"] = str(max(0, effective.times - count))
        if limited:
            raise RateLimitException(
                "Too many requests. Try again later.",
                retry_after=retry_after,
                headers={
                    "X-RateLimit-Limit": str(effective.times),
                    "X-RateLimit-Remaining": "0",
                },
            )

    @property
    def rate_limiter(self) -> "RateLimiterBackend | None":
        """The configured rate-limit backend."""
        return self.runtime.rate_limiter

    # --- shared routes -------------------------------------------------------
    def _shared_router(self) -> APIRouter:
        router = APIRouter(tags=["auth"])
        router.include_router(build_register_route(self, self._register_schema))
        password_field = (self.password_policy.body_field(), ...)
        SetPasswordModel = create_model(
            "_SetPasswordIn", __base__=_SetPasswordIn, new_password=password_field
        )
        ChangePasswordModel = create_model(
            "_ChangePasswordIn", __base__=_ChangePasswordIn, new_password=password_field
        )

        @router.get("/me")
        async def me(user: Annotated[Principal, Depends(self.current_user())]):
            """Return the authenticated user's identity, scopes, and auth transport."""
            return {
                "user_id": user.user_id,
                "username": self.repo.get(user.user, "username") if user.user else None,
                "email": self.repo.get(user.user, "email") if user.user else None,
                "is_superuser": user.is_superuser,
                "scopes": list(user.scopes),
                "via": user.transport,
            }

        @router.post("/set-password")
        async def set_password(
            body: SetPasswordModel,  # type: ignore[valid-type]
            principal: Annotated[Principal, Depends(self.current_user())],
            db: Annotated[Any, Depends(self.session)],
        ):
            """Set a password for an account that doesn't have one (OAuth-only).

            Note:
                The active session/credential IS the re-authentication - there's
                no current password to check because the account never had one.
                This is **set**, not **change**: it refuses (400) if the account
                already has a usable password (use the password-reset flow to
                change an existing one). It does not evict other sessions/tokens
                (establishing a first credential isn't a compromise response).

            Note:
                Allowed over any transport. On the session path the POST already
                carries CSRF; on the bearer path there's no CSRF surface (the
                token is sent explicitly, not auto-attached), and a valid bearer
                token is itself proof of the active credential - the same re-auth
                argument. Narrow with ``transport="session"`` if your policy
                requires first-password establishment to be browser-only.
            """
            user = principal.user
            new_password = cast(_SetPasswordIn, body).new_password
            if not is_unusable_password(self.repo.get(user, "hashed_password", "")):
                raise BadRequestException(
                    "Account already has a password; use the password reset flow to change it."
                )
            await self.validate_password(
                new_password, user=user, source="set", field="new_password"
            )
            await self.repo.update(db, user, {"hashed_password": get_password_hash(new_password)})
            return {"detail": "Password set."}

        @router.post(
            "/change-password",
            dependencies=[Depends(self.rate_limit("change_password", key=KeyBy.USER))],
        )
        async def change_password(
            body: ChangePasswordModel,  # type: ignore[valid-type]
            request: Request,
            principal: Annotated[Principal, Depends(self.current_user())],
            db: Annotated[Any, Depends(self.session)],
        ):
            """Change the password for an authenticated account, verifying the current one.

            Note:
                Re-auth is the *current password*: the active session/token proves
                presence, the current password proves intent. Allowed over any
                transport - CSRF is automatic on the session path, and bearer has
                no CSRF surface. An account with no usable password gets a 400
                (use ``/set-password`` to create the first one).

            Note:
                A password change is a compromise response: it bumps
                ``token_version`` (evicting bearer tokens; a no-op without the
                column) and revokes the user's OTHER sessions, keeping the current
                one. Same eviction shape as a password reset.
            """
            user = principal.user
            current_hash = self.repo.get(user, "hashed_password", "")
            if is_unusable_password(current_hash):
                raise BadRequestException(
                    "Account has no password; use /set-password to create one."
                )
            change = cast(_ChangePasswordIn, body)
            if not verify_password(change.current_password, current_hash):
                raise UnauthorizedException("Current password is incorrect.")
            await self.validate_password(
                change.new_password, user=user, source="change", field="new_password"
            )
            await self.repo.update(
                db, user, {"hashed_password": get_password_hash(change.new_password)}
            )
            await self.repo.increment_token_version(db, user)
            if self.sessions is not None:
                await self.sessions.revoke_all(
                    principal.user_id, exclude=principal.metadata.get("session_id")
                )
            await self.hooks.run_after_password_changed(
                self.repo.to_dict(user),
                db=db,
                context=HookContext(transport=principal.transport, request=request),
            )
            return {"detail": "Password changed."}

        if self._session_transport is not None and self._session_transport.management_routes:
            self._add_session_management_routes(router)

        return router

    def _add_session_management_routes(self, router: APIRouter) -> None:
        """Mount the opt-in session/CSRF management routes (``SessionTransport(management_routes=True)``)."""
        sessions = self.sessions
        assert sessions is not None
        session_user = self.current_user(transport="session")

        @router.post(
            "/logout-all",
            dependencies=[Depends(self.rate_limit("logout_all", key=KeyBy.USER))],
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

        @router.delete("/sessions/{session_id}")
        async def revoke_session(
            session_id: str,
            response: Response,
            principal: Annotated[Principal, Depends(session_user)],
        ):
            """Revoke one session by id (ownership-checked; 404 also covers 'not yours')."""
            ok = await sessions.revoke(session_id, owner_id=principal.user_id)
            if not ok:
                raise NotFoundException("Session not found.")
            if session_id == principal.metadata.get("session_id"):
                sessions.clear_session_cookies(response)
            return {"detail": "Session revoked."}

        @router.post(
            "/csrf/refresh",
            dependencies=[Depends(self.rate_limit("csrf_refresh", key=KeyBy.IP))],
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
                token = cookie
            else:
                token = await sessions.regenerate_csrf_token(session.user_id, session_id)
                max_age = (
                    sessions.timeout_seconds_for(session.metadata)
                    if session.metadata.get(REMEMBER_ME_META_KEY)
                    else None
                )
                sessions.set_csrf_cookie(response, token, max_age=max_age)
            return {"csrf_token": token}

    # --- assembled routers ---------------------------------------------------
    @property
    def router(self) -> APIRouter:
        """The full router to mount: shared (``/register``, ``/me``) plus every
        transport's routes, plus OAuth and email routes when configured.

        Returns:
            An `APIRouter` to pass to ``app.include_router``.

        Example:
            ```python
            app.include_router(auth.router)
            ```
        """
        router = APIRouter()
        router.include_router(self._shared_router())
        for t in self.transports:
            sub = t.contributes_routes()
            if sub is not None:
                router.include_router(sub)
        if self._oauth_router is not None:
            router.include_router(self._oauth_router)
        if self._email_service is not None:
            router.include_router(build_email_router(auth=self, service=self._email_service))
        return router

    @property
    def session_router(self) -> APIRouter:
        """Only the session transport's routes (``/login``, ``/logout``).

        Raises:
            RuntimeError: If no [SessionTransport][crudauth.transports.session.transport.SessionTransport] is configured.
        """
        if self._session_transport is None:
            raise RuntimeError("No SessionTransport configured")
        return self._session_transport.contributes_routes()

    @property
    def bearer_router(self) -> APIRouter:
        """Only the bearer transport's routes (``/token``, ``/refresh``).

        Raises:
            RuntimeError: If no [BearerTransport][crudauth.transports.bearer.transport.BearerTransport] is configured.
        """
        bearer = next((t for t in self.transports if isinstance(t, BearerTransport)), None)
        if bearer is None:
            raise RuntimeError("No BearerTransport configured")
        return bearer.contributes_routes()

    # --- lifecycle -----------------------------------------------------------
    async def initialize(self) -> None:
        """Open storage/limiter connections; call from your app's lifespan startup.

        Idempotent per component. Required for server-side backends (redis); a
        no-op for the in-memory defaults.

        Example:
            ```python
            @asynccontextmanager
            async def lifespan(app):
                await auth.initialize()
                yield
                await auth.shutdown()
            ```
        """
        if self.runtime.rate_limiter is not None:
            await self.runtime.rate_limiter.initialize()
        for t in self.transports:
            await t.initialize()
        if self._oauth_state_storage is not None:
            await self._oauth_state_storage.initialize()
        if self._email_token_store is not None:
            await self._email_token_store.initialize()

    async def shutdown(self) -> None:
        """Close connections. Call in lifespan teardown."""
        for t in self.transports:
            await t.shutdown()
        if self._oauth_state_storage is not None:
            await self._oauth_state_storage.close()
        if self._email_token_store is not None:
            await self._email_token_store.close()
        if self.runtime.rate_limiter is not None:
            await self.runtime.rate_limiter.close()
        if self._owned_redis is not None:
            await self._owned_redis.aclose()

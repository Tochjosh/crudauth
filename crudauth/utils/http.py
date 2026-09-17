"""Request-level helpers: site boundary, client IP, redirect targets."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from fastapi import Request

from ..constants import IPV6_CLIENT_PREFIX_LENGTH

__all__ = ["is_cross_site", "get_client_ip", "client_ip_key", "safe_redirect_path"]


def is_cross_site(request: Request) -> bool:
    """Whether the browser marked ``request`` as sent from another site (``Sec-Fetch-Site``).

    A request without the header (an API client, an older browser) isn't cross-site.
    """
    return request.headers.get("sec-fetch-site") == "cross-site"


def get_client_ip(request: Request, trusted_hops: int = 0) -> str:
    """Resolve the client IP with a trusted-proxy boundary.

    ``X-Forwarded-For`` is client-controllable at its left end, so honoring it
    blindly lets an attacker forge a fresh IP per request and slip every per-IP
    rate limit and lockout. This function only consults the header when the app
    declares how many trusted proxies sit in front of it.

    Args:
        request: The incoming request.
        trusted_hops: Number of trusted reverse proxies in front of the app.
            ``0`` (default) ignores forwarding headers entirely and uses the
            socket peer - correct when the app is directly exposed. ``N`` reads
            the ``N``-th ``X-Forwarded-For`` entry from the right: each trusted
            proxy appends the address it received the request from, so that
            entry is the client address your outermost proxy saw, and values an
            attacker prepends sit further left where they are never read. A
            chain shorter than ``N`` resolves to its left-most entry. Repeated
            ``X-Forwarded-For`` header lines are read as one list, in order.

    Returns:
        The resolved client IP, or ``"unknown"`` if it cannot be determined.

    Example:
        ```python
        # App behind a single trusted reverse proxy (e.g. nginx, Caddy):
        CRUDAuth(..., trusted_proxy_hops=1)
        ```
    """
    if trusted_hops > 0:
        forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-min(trusted_hops, len(parts))]
    if request.client is not None:
        return request.client.host
    return "unknown"


def client_ip_key(ip: str) -> str:
    """The rate-limit and lockout key for a client IP.

    An IPv4 address keys as itself. An IPv6 client keys by its ``/64`` network,
    the smallest block a single subscriber is normally assigned, so rotating
    addresses inside one allocation can't mint fresh budgets. An IPv4-mapped IPv6
    address keys as its IPv4 address. Anything that isn't an IP (``"unknown"``)
    is returned unchanged.

    Example:
        ```python
        client_ip_key("2001:db8:1:2:3:4:5:6")  # "2001:db8:1:2::/64"
        client_ip_key("::ffff:203.0.113.7")    # "203.0.113.7"
        ```
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(address, ipaddress.IPv4Address):
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(ipaddress.IPv6Network((address, IPV6_CLIENT_PREFIX_LENGTH), strict=False))


def safe_redirect_path(target: str | None, default: str = "/") -> str:
    """Return a safe same-origin redirect path, or ``default`` when rejected.

    Only single-slash-rooted relative paths are accepted. Absolute URLs,
    protocol-relative URLs, backslashes, control characters, and values with a
    URL scheme or network location are rejected. Use this for client-supplied
    post-login or post-logout redirect targets to prevent open redirects.

    Args:
        target: The untrusted redirect target.
        default: The fallback path returned for an unsafe or missing target.
    """
    if not target or not target.startswith("/") or target.startswith("//"):
        return default
    if "\\" in target or any(ord(c) < 0x20 for c in target):
        return default
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return default
    return target

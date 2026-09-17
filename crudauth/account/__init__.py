"""Routes that act on the signed-in account: identity and passwords."""

from .router import build_account_router

__all__ = ["build_account_router"]

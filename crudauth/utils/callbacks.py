"""Introspection of user-supplied callbacks."""

from __future__ import annotations

import inspect
from typing import Any, Callable

__all__ = ["takes_two_arguments"]


def takes_two_arguments(callback: Callable[..., Any]) -> bool:
    """Whether ``callback`` takes at least two required positional arguments.

    Decides whether a callback that may accept an optional second argument (a
    rate-limit key, a password validator) is called with it.
    """
    try:
        params = inspect.signature(callback).parameters
    except (ValueError, TypeError):
        return False
    required_positional = sum(
        1
        for p in params.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) and p.default is p.empty
    )
    return required_positional >= 2

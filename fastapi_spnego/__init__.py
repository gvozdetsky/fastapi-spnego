"""fastapi-spnego — SPNEGO / Kerberos (HTTP Negotiate) auth for FastAPI & Starlette."""

from __future__ import annotations

from .backend import GSSAPIBackend, SpnegoBackend, default_backend
from .ccache import cleanup, store_delegated, ticket_lifetime
from .config import SpnegoConfig
from .dependencies import SpnegoAuth
from .exceptions import (
    BackendUnavailableError,
    NegotiateChallenge,
    NegotiateFailedError,
    SpnegoError,
)
from .middleware import SpnegoMiddleware
from .models import NegotiateResult, SpnegoIdentity

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("fastapi-spnego")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0+unknown"

__all__ = [
    "SpnegoAuth",
    "SpnegoMiddleware",
    "SpnegoIdentity",
    "SpnegoConfig",
    "SpnegoBackend",
    "GSSAPIBackend",
    "default_backend",
    "NegotiateResult",
    "SpnegoError",
    "BackendUnavailableError",
    "NegotiateFailedError",
    "NegotiateChallenge",
    # Delegated-credential (ccache) lifecycle helpers.
    "store_delegated",
    "ticket_lifetime",
    "cleanup",
]

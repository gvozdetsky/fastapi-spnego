"""fastapi-spnego — SPNEGO / Kerberos (HTTP Negotiate) auth for FastAPI & Starlette."""

from __future__ import annotations

from .backend import GSSAPIBackend, SpnegoBackend, default_backend
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

__version__ = "0.1.0"

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
]

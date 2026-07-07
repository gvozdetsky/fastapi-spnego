"""Exception types for fastapi-spnego."""

from __future__ import annotations

from starlette.exceptions import HTTPException


class SpnegoError(Exception):
    """Base class for all fastapi-spnego errors."""


class BackendUnavailableError(SpnegoError):
    """Raised when the requested GSSAPI/SSPI backend cannot be loaded.

    On Linux/macOS this usually means the ``gssapi`` package (and system
    ``libkrb5``) is not installed; on Windows, that the SSPI backend is missing.
    """


class NegotiateFailedError(SpnegoError):
    """Raised when the client token is present but validation fails."""


class NegotiateChallenge(HTTPException):
    """A 401 that asks the client to perform (or continue) the Negotiate handshake.

    Because this subclasses Starlette's :class:`HTTPException`, FastAPI renders it
    automatically — including the ``WWW-Authenticate`` header that triggers the
    browser's Kerberos/SPNEGO flow.

    :param out_token: base64 continuation token for a multi-leg handshake. When
        ``None`` the bare ``Negotiate`` challenge is sent (the initial prompt).
    """

    def __init__(self, out_token: str | None = None, detail: str = "Unauthorized") -> None:
        value = "Negotiate" if out_token is None else f"Negotiate {out_token}"
        super().__init__(status_code=401, detail=detail, headers={"WWW-Authenticate": value})

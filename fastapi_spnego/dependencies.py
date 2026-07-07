"""The FastAPI dependency that performs SPNEGO/Negotiate authentication.

Usage::

    from fastapi import Depends, FastAPI
    from fastapi_spnego import SpnegoAuth, SpnegoIdentity

    app = FastAPI()
    spnego = SpnegoAuth()

    @app.get("/whoami")
    def whoami(identity: SpnegoIdentity = Depends(spnego)):
        return {"user": identity.username, "realm": identity.realm}

This is deliberately a `Depends()`-able object rather than a global/middleware:
it fits FastAPI's dependency-injection model, is trivially overridable in tests,
and composes with the rest of an app's auth (map ``identity.principal`` to a user).
"""

from __future__ import annotations

import logging

from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from .backend import SpnegoBackend, default_backend
from .config import SpnegoConfig
from .exceptions import NegotiateChallenge, NegotiateFailedError
from .models import SpnegoIdentity

logger = logging.getLogger("fastapi_spnego")

_PREFIX = "negotiate "


class SpnegoAuth:
    """Callable FastAPI dependency verifying the ``Authorization: Negotiate`` header.

    :param backend: a :class:`SpnegoBackend`. Defaults to the platform default.
    :param config: settings; only used to build the default backend / read
        ``auto_error``. Ignored when ``backend`` is supplied explicitly.
    """

    def __init__(
        self,
        backend: SpnegoBackend | None = None,
        config: SpnegoConfig | None = None,
    ) -> None:
        self.config = config or SpnegoConfig()
        self.backend = backend or default_backend(self.config)

    async def __call__(self, request: Request, response: Response) -> SpnegoIdentity | None:
        header = request.headers.get("Authorization")

        if not header or not header.lower().startswith(_PREFIX):
            # No token yet — prompt the client to start the handshake.
            if self.config.auto_error:
                raise NegotiateChallenge()  # 401 + `WWW-Authenticate: Negotiate`
            return None

        in_token = header[len(_PREFIX) :].strip()

        # GSSAPI is blocking C code; keep it off the event loop.
        try:
            result = await run_in_threadpool(self.backend.step, in_token)
        except NegotiateFailedError as exc:
            # The client presented a token but validation failed (malformed,
            # wrong realm, clock skew, etc.). That is a client error, not a
            # server crash — never let it surface as a 500. Return 403 rather
            # than a fresh 401 challenge so a broken client cannot spin in a
            # challenge/retry loop. Details are logged, never sent to the client.
            logger.warning("Negotiate authentication failed: %s", exc)
            if self.config.auto_error:
                raise HTTPException(
                    status_code=403, detail="Negotiate authentication failed"
                ) from None
            return None

        if not result.complete:
            # Multi-leg (e.g. NTLM): bounce the continuation token back as a 401.
            raise NegotiateChallenge(out_token=result.out_token)

        # Mutual authentication: return the final server token to the client.
        if result.out_token:
            response.headers["WWW-Authenticate"] = f"Negotiate {result.out_token}"

        if result.identity is None:
            # A completed handshake must yield an identity; a backend that
            # reports otherwise is buggy. Fail closed rather than return None.
            logger.error("Backend reported a complete handshake with no identity")
            raise HTTPException(status_code=403, detail="Negotiate authentication failed")

        return result.identity

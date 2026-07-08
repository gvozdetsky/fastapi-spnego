"""Optional ASGI middleware variant.

Most apps should use the :class:`~fastapi_spnego.dependencies.SpnegoAuth`
dependency — it is explicit, per-route, and trivially testable. Reach for this
middleware only when you want Negotiate applied *globally* and the identity
stashed on ``request.state`` (closer to a Flask ``before_request`` hook).

The middleware runs the same backend ``step()`` flow as the dependency::

    from fastapi import FastAPI, Request
    from fastapi_spnego import SpnegoMiddleware

    app = FastAPI()
    app.add_middleware(SpnegoMiddleware, exclude_paths=["/health", "/metrics"])

    @app.get("/whoami")
    def whoami(request: Request):
        identity = request.state.spnego_identity
        return {"user": identity.username}

Design notes:

- Blocking GSSAPI work runs in a threadpool, exactly as in the dependency.
- ``exclude_paths`` are matched as prefixes so health checks, metrics, and
  static assets can stay unauthenticated.
- ``auth_required`` is an optional per-request predicate ``(scope) -> bool``
  (sync or async) for finer control than path prefixes — e.g. enforce auth on
  writes but leave ``GET`` optional.
- On success the authenticated :class:`SpnegoIdentity` is placed on
  ``request.state.spnego_identity`` and the mutual-auth token (if any) is added
  to the response's ``WWW-Authenticate`` header.
- With ``auto_error=False`` unauthenticated requests are allowed through with
  ``request.state.spnego_identity is None`` instead of being challenged.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .backend import SpnegoBackend, default_backend
from .config import SpnegoConfig
from .exceptions import NegotiateFailedError

logger = logging.getLogger("fastapi_spnego")

_PREFIX = "negotiate "

#: A predicate deciding, per request, whether Negotiate auth is enforced. It
#: receives the ASGI ``scope`` and returns a bool (or an awaitable of one), so it
#: can branch on method, path, headers, etc. See ``SpnegoMiddleware.auth_required``.
AuthRequired = Callable[[Scope], bool | Awaitable[bool]]


class SpnegoMiddleware:
    """Apply SPNEGO/Negotiate authentication to every (non-excluded) request.

    :param app: the wrapped ASGI application.
    :param backend: a :class:`SpnegoBackend`; defaults to the platform default.
    :param config: settings; used to build the default backend and read
        ``auto_error``. Ignored for backend selection when ``backend`` is given.
    :param exclude_paths: request-path prefixes that skip authentication
        entirely (e.g. ``["/health", "/metrics"]``).
    :param auth_required: optional predicate ``(scope) -> bool`` (sync or async)
        evaluated per request to decide whether authentication is enforced. It is
        more expressive than ``exclude_paths`` (which only matches path prefixes):
        branch on method, headers, or anything in the scope, e.g.
        ``auth_required=lambda scope: scope["method"] != "GET"``. When it returns
        ``False`` the request is treated as optional auth for that call — a valid
        token still populates ``request.state.spnego_identity``, but a missing or
        invalid one passes through with identity ``None`` instead of challenging.
        When given, it overrides ``config.auto_error`` for the enforce decision;
        ``exclude_paths`` still short-circuits first.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        backend: SpnegoBackend | None = None,
        config: SpnegoConfig | None = None,
        exclude_paths: Iterable[str] | None = None,
        auth_required: AuthRequired | None = None,
    ) -> None:
        self.app = app
        self.config = config or SpnegoConfig()
        self.backend = backend or default_backend(self.config)
        self.exclude_paths: Sequence[str] = tuple(exclude_paths or ())
        self.auth_required = auth_required

    def _excluded(self, path: str) -> bool:
        return any(path == p or path.startswith(p) for p in self.exclude_paths)

    async def _enforce(self, scope: Scope) -> bool:
        """Whether to challenge/reject this request when auth is absent or bad.

        With no ``auth_required`` predicate this is just ``config.auto_error``;
        otherwise the predicate decides per request (and may be async).
        """
        if self.auth_required is None:
            return self.config.auto_error
        result = self.auth_required(scope)
        if inspect.isawaitable(result):
            result = await result
        return bool(result)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self._excluded(scope["path"]):
            await self.app(scope, receive, send)
            return

        enforce = await self._enforce(scope)
        header = Headers(scope=scope).get("Authorization")

        if not header or not header.lower().startswith(_PREFIX):
            if enforce:
                await self._challenge(scope, receive, send)
                return
            self._set_identity(scope, None)
            await self.app(scope, receive, send)
            return

        in_token = header[len(_PREFIX) :].strip()

        try:
            result = await run_in_threadpool(self.backend.step, in_token)
        except NegotiateFailedError as exc:
            logger.warning("Negotiate authentication failed: %s", exc)
            if enforce:
                await self._forbidden(scope, receive, send)
                return
            self._set_identity(scope, None)
            await self.app(scope, receive, send)
            return

        if not result.complete:
            await self._challenge(scope, receive, send, out_token=result.out_token)
            return

        if result.identity is None:
            logger.error("Backend reported a complete handshake with no identity")
            await self._forbidden(scope, receive, send)
            return

        self._set_identity(scope, result.identity)

        # Add the mutual-auth token to the real response as it starts.
        if result.out_token:
            await self.app(scope, receive, self._wrap_send(send, result.out_token))
        else:
            await self.app(scope, receive, send)

    @staticmethod
    def _set_identity(scope: Scope, identity: object | None) -> None:
        scope.setdefault("state", {})["spnego_identity"] = identity

    @staticmethod
    def _wrap_send(send: Send, out_token: str) -> Send:
        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.append("WWW-Authenticate", f"Negotiate {out_token}")
            await send(message)

        return wrapped

    async def _challenge(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        out_token: str | None = None,
    ) -> None:
        value = "Negotiate" if out_token is None else f"Negotiate {out_token}"
        response = PlainTextResponse(
            "Unauthorized", status_code=401, headers={"WWW-Authenticate": value}
        )
        await response(scope, receive, send)

    async def _forbidden(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = PlainTextResponse("Negotiate authentication failed", status_code=403)
        await response(scope, receive, send)

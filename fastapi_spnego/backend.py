"""SPNEGO accept-context backends.

A backend performs the server side of one Negotiate leg: given the base64 token
the client sent, it advances the GSSAPI/SSPI security context and reports whether
the handshake is complete (and, if so, who the client is).

The GSSAPI accept logic here is adapted from pgAdmin's proven implementation in
``web/pgadmin/authenticate/kerberos.py`` (``negotiate_start``), lifted out of Flask.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Protocol, runtime_checkable

from .ccache import store_delegated
from .config import SpnegoConfig
from .exceptions import BackendUnavailableError, NegotiateFailedError
from .models import NegotiateResult, SpnegoIdentity

logger = logging.getLogger("fastapi_spnego")


@runtime_checkable
class SpnegoBackend(Protocol):
    """Protocol every backend implements. Backends are stateless per call for
    single-leg Kerberos; multi-leg (NTLM) state handling is a roadmap concern."""

    def step(self, in_token_b64: str) -> NegotiateResult:
        """Advance the accept context with the client's base64 Negotiate token."""
        ...


class GSSAPIBackend:
    """Accept SPNEGO/Kerberos tokens via the ``gssapi`` library (Linux/macOS).

    This backend can additionally capture *delegated* credentials, which the
    ``pyspnego`` backend cannot — so it is the default where available.
    """

    def __init__(self, config: SpnegoConfig | None = None) -> None:
        self.config = config or SpnegoConfig()

        try:
            import gssapi  # noqa: F401
        except (ImportError, OSError) as exc:  # OSError: Windows without KfW libs
            raise BackendUnavailableError(
                "The GSSAPI backend requires the 'gssapi' package and system "
                "Kerberos libraries (e.g. libkrb5-dev). Install with "
                "`pip install fastapi-spnego[gssapi]`."
            ) from exc

        # Point GSSAPI at the configured keytab, matching pgAdmin's behaviour.
        if self.config.keytab:
            os.environ["KRB5_KTNAME"] = self.config.keytab

    def _server_creds(self):  # type: ignore[no-untyped-def]
        import gssapi

        if self.config.accept_any_principal:
            # GSS_C_NO_NAME: accept whichever service principal the client's ticket
            # targets, provided it exists in the keytab. Robust behind reverse
            # proxies / with multi-SPN keytabs. See SpnegoConfig.accept_any_principal.
            return gssapi.Credentials(usage="accept")

        name = gssapi.Name(self.config.service_name, name_type=gssapi.NameType.hostbased_service)
        cname = name.canonicalize(gssapi.MechType.kerberos)
        return gssapi.Credentials(usage="accept", name=cname)

    def step(self, in_token_b64: str) -> NegotiateResult:
        import gssapi

        try:
            context = gssapi.SecurityContext(creds=self._server_creds())
            out_token = context.step(base64.b64decode(in_token_b64))
        except Exception as exc:  # noqa: BLE001 — surface as our error type
            raise NegotiateFailedError(str(exc)) from exc

        out_b64 = base64.b64encode(out_token).decode() if out_token else None

        if not context.complete:
            # Continuation leg: hand the token back so the client can respond.
            return NegotiateResult(complete=False, out_token=out_b64)

        principal = str(context.initiator_name)
        extra: dict[str, object] = {}

        # Ticket lifetime is handy for downstream session/expiry decisions.
        lifetime = getattr(context, "lifetime", None)
        if lifetime is not None:
            extra["ticket_lifetime"] = lifetime

        delegated_ccache = self._capture_delegation(context)

        identity = SpnegoIdentity.from_principal(
            principal, delegated_ccache=delegated_ccache, extra=extra
        )
        return NegotiateResult(complete=True, out_token=out_b64, identity=identity)

    def _capture_delegation(self, context: object) -> str | None:
        """Store forwarded client credentials to a ccache, if enabled and present.

        Never fails the handshake: a delegation problem downgrades to "no ccache"
        with a warning, since the client is already authenticated. Mirrors the
        ``deleg_creds.store(...)`` path in pgAdmin's ``negotiate_start``.
        """
        if not self.config.allow_delegation:
            return None
        try:
            deleg_creds = getattr(context, "delegated_creds", None)
            return store_delegated(deleg_creds, self.config)
        except Exception as exc:  # noqa: BLE001 — delegation is best-effort
            logger.warning("Could not capture delegated credentials: %s", exc)
            return None


def default_backend(config: SpnegoConfig | None = None) -> SpnegoBackend:
    """Return the best available backend for the current platform.

    Currently GSSAPI-only. Once the pyspnego backend lands this will prefer it on
    Windows (SSPI) and fall back to GSSAPI elsewhere.
    """
    return GSSAPIBackend(config)

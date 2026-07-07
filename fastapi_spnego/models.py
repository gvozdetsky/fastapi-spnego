"""Data models returned by the SPNEGO handshake."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SpnegoIdentity:
    """The authenticated client identity resulting from a completed handshake.

    Returned by :class:`~fastapi_spnego.dependencies.SpnegoAuth` as the value of
    the dependency. The application maps ``principal`` to its own user model.
    """

    #: The full initiator principal, e.g. ``"alice@EXAMPLE.COM"``.
    principal: str

    #: The local part of the principal (before ``@``), e.g. ``"alice"``.
    username: str

    #: The realm (after ``@``), e.g. ``"EXAMPLE.COM"``. May be ``None``.
    realm: str | None = None

    #: Path to a credentials cache holding delegated credentials, if the client
    #: forwarded (delegated) a TGT and delegation capture is enabled. Else ``None``.
    delegated_ccache: str | None = None

    #: Backend-specific extras (e.g. ticket lifetime). Not part of the stable API.
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_principal(cls, principal: str, **kwargs: Any) -> SpnegoIdentity:
        username, _, realm = principal.partition("@")
        return cls(principal=principal, username=username, realm=realm or None, **kwargs)


@dataclass
class NegotiateResult:
    """Result of a single accept-context step performed by a backend."""

    #: True when the security context is fully established.
    complete: bool

    #: Base64 token to send back to the client via ``WWW-Authenticate: Negotiate``.
    #: Present both for mutual-auth on completion and for continuation legs.
    out_token: str | None = None

    #: The established identity. Only set when ``complete`` is True.
    identity: SpnegoIdentity | None = None

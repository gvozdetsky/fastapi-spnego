"""Configuration for the SPNEGO provider."""

from __future__ import annotations

import socket

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SpnegoConfig(BaseSettings):
    """Settings for the Negotiate handshake. Read from ``SPNEGO_`` env vars.

    Example::

        SPNEGO_SERVICE=HTTP
        SPNEGO_HOSTNAME=pgadmin.example.com
        SPNEGO_KEYTAB=/etc/pgadmin.keytab
    """

    model_config = SettingsConfigDict(env_prefix="SPNEGO_", extra="ignore")

    #: Service class of the server principal. Almost always ``HTTP`` for web apps.
    service: str = "HTTP"

    #: FQDN the service principal is registered under (``HTTP/<hostname>@REALM``).
    #: Defaults to the machine hostname; set explicitly behind a reverse proxy.
    #: Resolved per-instance (``default_factory``) rather than once at import.
    hostname: str = Field(default_factory=socket.getfqdn)

    #: Path to the service keytab. If set, exported as ``KRB5_KTNAME`` so GSSAPI
    #: can find it. If unset, the ambient ``KRB5_KTNAME`` / default keytab is used.
    keytab: str | None = None

    #: When True, capture forwarded (delegated) client credentials into a ccache
    #: under ``ccache_dir`` so the app can act on the user's behalf. See ccache.py.
    allow_delegation: bool = False

    #: Directory for delegated-credential ccache files. Must be writable, 0700.
    ccache_dir: str = "/tmp/fastapi_spnego_ccache"

    #: When True (default) a missing/invalid header raises 401 with a challenge.
    #: When False the dependency returns ``None`` instead (useful for optional auth).
    auto_error: bool = True

    @property
    def service_name(self) -> str:
        """The hostbased service name, e.g. ``HTTP@pgadmin.example.com``."""
        return f"{self.service}@{self.hostname}"

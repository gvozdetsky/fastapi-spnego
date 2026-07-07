"""Delegated-credential (ccache) handling.

When a client forwards (delegates) its TGT during the handshake — and the SPN is
flagged *trusted for delegation* in the directory — the server receives a set of
delegated credentials. Storing them in a Kerberos credentials cache lets the app
subsequently act on the user's behalf (e.g. connect onward to a database as that
user). This mirrors the ``deleg_creds.store(...)`` path in pgAdmin's
``kerberos.py`` (``negotiate_start``), generalised for a multi-user server.

Only :class:`~fastapi_spnego.backend.GSSAPIBackend` populates this — the
``pyspnego``/SSPI backend cannot capture delegated credentials.
"""

from __future__ import annotations

import logging
import os
import re

from .config import SpnegoConfig
from .exceptions import BackendUnavailableError

logger = logging.getLogger("fastapi_spnego")

#: Characters allowed verbatim in a ccache filename; everything else (notably the
#: ``/`` and ``@`` in a principal) is replaced so the name is filesystem-safe.
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")


def _ensure_ccache_dir(config: SpnegoConfig) -> None:
    """Create the ccache directory if needed, restricted to the owner (0700)."""
    os.makedirs(config.ccache_dir, mode=0o700, exist_ok=True)
    # makedirs honours the mode only on creation; enforce it if it pre-existed.
    os.chmod(config.ccache_dir, 0o700)


def _ccache_path(config: SpnegoConfig, principal: str) -> str:
    safe = _UNSAFE.sub("_", principal)
    return os.path.join(config.ccache_dir, f"cache_{safe}")


def store_delegated(delegated_creds: object, config: SpnegoConfig) -> str | None:
    """Store delegated credentials to a per-user ccache and return its handle.

    :param delegated_creds: the ``context.delegated_creds`` from a completed
        GSSAPI accept context, or ``None`` if the client did not delegate.
    :param config: provides ``ccache_dir``.
    :returns: a ``FILE:<path>`` ccache handle suitable for ``KRB5CCNAME``, or
        ``None`` when there were no credentials to store.

    Unlike pgAdmin (a single-user desktop app) this does **not** set the process
    default ccache — a shared server handles many users at once, so each identity
    gets its own cache and the handle is returned for the caller to use
    explicitly (e.g. ``KRB5CCNAME=<handle>`` on an onward connection).
    """
    if delegated_creds is None:
        return None

    # gssapi raises when a context completed without delegation; guard on `name`.
    name = getattr(delegated_creds, "name", None)
    if name is None:
        return None

    _ensure_ccache_dir(config)
    path = _ccache_path(config, str(name))
    handle = f"FILE:{path}"
    # store() is part of the gssapi.Credentials API; typed as object here so this
    # module imports without the optional gssapi dependency present.
    delegated_creds.store(  # type: ignore[attr-defined]
        {"ccache": handle}, overwrite=True, set_default=False
    )
    os.chmod(path, 0o600)
    logger.debug("Stored delegated credentials for %s at %s", name, handle)
    return handle


def ticket_lifetime(handle: str | None) -> int | None:
    """Return the remaining lifetime, in seconds, of a stored delegated ccache.

    Mirrors pgAdmin's ``validate_ticket``: open the credentials cache and read the
    remaining validity of the delegated ticket. Useful for deciding when an app
    session backed by delegated credentials should be considered expired.

    :param handle: a ``FILE:<path>`` ccache handle (or bare path) as returned by
        :func:`store_delegated` / ``SpnegoIdentity.delegated_ccache``.
    :returns: remaining seconds, or ``None`` if ``handle`` is empty, the ccache is
        missing/unreadable, or the credentials have already expired.
    :raises BackendUnavailableError: if the ``gssapi`` package is not installed.
    """
    if not handle:
        return None
    try:
        import gssapi
    except (ImportError, OSError) as exc:
        raise BackendUnavailableError(
            "ticket_lifetime requires the 'gssapi' package; "
            "install with `pip install fastapi-spnego[gssapi]`."
        ) from exc
    try:
        creds = gssapi.Credentials(store={"ccache": handle})
        lifetime = creds.lifetime
    except Exception as exc:  # noqa: BLE001 — missing ccache or expired creds
        logger.debug("Could not read ticket lifetime from %s: %s", handle, exc)
        return None
    return int(lifetime) if lifetime else None


def cleanup(handle: str | None) -> None:
    """Remove a ccache previously created by :func:`store_delegated`.

    Accepts either a bare path or a ``FILE:<path>`` handle. Missing files are
    ignored, so this is safe to call unconditionally on logout/teardown.
    """
    if not handle:
        return
    path = handle[len("FILE:") :] if handle.startswith("FILE:") else handle
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:  # pragma: no cover - defensive
        logger.warning("Failed to remove ccache %s: %s", path, exc)

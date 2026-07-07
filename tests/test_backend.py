"""Unit tests for GSSAPIBackend credential selection.

The real accept path is covered by the Docker KDC integration suite; here we use
a fake ``gssapi`` module to assert *which* server credentials the backend asks
for — in particular that ``accept_any_principal`` drops the pinned name.
"""

from __future__ import annotations

import sys
import types

from fastapi_spnego.backend import GSSAPIBackend
from fastapi_spnego.config import SpnegoConfig


def _fake_gssapi(record: dict) -> types.ModuleType:
    mod = types.ModuleType("gssapi")

    class Credentials:
        def __init__(self, usage=None, name=None):  # type: ignore[no-untyped-def]
            record["usage"] = usage
            record["name"] = name

    class _CanonName:
        pass

    class Name:
        def __init__(self, base, name_type=None):  # type: ignore[no-untyped-def]
            record["name_input"] = base

        def canonicalize(self, mech):  # type: ignore[no-untyped-def]
            return _CanonName()

    mod.Credentials = Credentials  # type: ignore[attr-defined]
    mod.Name = Name  # type: ignore[attr-defined]
    mod.NameType = types.SimpleNamespace(hostbased_service="hostbased")  # type: ignore[attr-defined]
    mod.MechType = types.SimpleNamespace(kerberos="krb5")  # type: ignore[attr-defined]
    return mod


def test_pins_service_name_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    record: dict = {}
    monkeypatch.setitem(sys.modules, "gssapi", _fake_gssapi(record))
    backend = GSSAPIBackend(SpnegoConfig(service="HTTP", hostname="app.example.com"))
    backend._server_creds()
    assert record["name_input"] == "HTTP@app.example.com"
    assert record["name"] is not None  # a pinned, canonicalized name is passed
    assert record["usage"] == "accept"


def test_accept_any_principal_uses_no_name(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    record: dict = {}
    monkeypatch.setitem(sys.modules, "gssapi", _fake_gssapi(record))
    backend = GSSAPIBackend(SpnegoConfig(accept_any_principal=True, hostname="ignored"))
    backend._server_creds()
    # GSS_C_NO_NAME → accept whatever principal in the keytab the ticket targets.
    assert record["name"] is None
    assert record["usage"] == "accept"

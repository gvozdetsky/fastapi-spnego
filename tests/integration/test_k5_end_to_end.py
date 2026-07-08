"""End-to-end SPNEGO/Kerberos test against an in-process MIT KDC.

Like ``test_gssapi_end_to_end.py`` this exercises the *real* GSSAPI accept path
— a genuine Negotiate handshake, not a fake backend — but it needs no Docker and
no reverse proxy. ``k5test`` spins up an ephemeral MIT KDC inside the test
process, so the whole client→server handshake runs in a single ``pytest`` job as
long as the system Kerberos stack (``libkrb5`` + the MIT ``krb5kdc``/``kadmin``
binaries) is present.

Run it with the integration extras installed::

    uv run --group gssapi pytest tests/integration/test_k5_end_to_end.py

When ``gssapi``/``k5test`` or the KDC binaries are missing the module skips
itself, so the normal unit-test run is unaffected. Delegation is intentionally
left to the Docker test, which drives a real forwardable-ticket client.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

# Only meaningful with the GSSAPI backend and an in-process KDC available.
gssapi = pytest.importorskip("gssapi")
pytest.importorskip("k5test")

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def krb_realm() -> Iterator[object]:
    """Start an ephemeral MIT KDC and point the process's Kerberos env at it.

    The realm auto-creates a ``user`` principal (with a TGT in the default
    ccache) and a ``host/<hostname>`` service principal extracted into the
    default keytab — everything both handshake legs need. Env vars are restored
    afterwards so nothing leaks into other tests.
    """
    from k5test import K5Realm

    try:
        # rdns=false keeps hostbased-service canonicalization from doing reverse
        # DNS, which would be flaky in CI containers.
        realm = K5Realm(krb5_conf={"libdefaults": {"rdns": "false"}})
    except Exception as exc:  # noqa: BLE001 — missing krb5kdc/kadmin binaries, etc.
        pytest.skip(f"could not start an in-process KDC: {exc}")

    saved = {key: os.environ.get(key) for key in realm.env}
    os.environ.update(realm.env)
    try:
        yield realm
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        realm.stop()


def _negotiate_token(realm: object, *, flags: list | None = None) -> tuple[object, str]:
    """Produce the client's initial Negotiate token for the realm's host SPN.

    Targets ``host/<hostname>`` directly as a Kerberos principal (rather than a
    hostbased service) so the name matches the principal k5test created verbatim,
    independent of DNS. Returns the live client context (to verify the mutual-auth
    reply) and the base64 token for the ``Authorization`` header.
    """
    service = gssapi.Name(
        f"host/{realm.hostname}", name_type=gssapi.NameType.kerberos_principal
    )
    ctx = gssapi.SecurityContext(name=service, usage="initiate", flags=flags)
    token = ctx.step()
    return ctx, base64.b64encode(token).decode("ascii")


def _dependency_app() -> object:
    from fastapi import Depends, FastAPI

    from fastapi_spnego import SpnegoAuth, SpnegoConfig, SpnegoIdentity

    # accept_any_principal: take whatever SPN the realm put in the keytab, so the
    # test needn't reconstruct the server's exact FQDN.
    spnego = SpnegoAuth(config=SpnegoConfig(accept_any_principal=True))
    app = FastAPI()

    @app.get("/whoami")
    def whoami(identity: SpnegoIdentity = Depends(spnego)) -> dict:
        return {
            "principal": identity.principal,
            "username": identity.username,
            "realm": identity.realm,
        }

    return app


def _middleware_app() -> object:
    from fastapi import FastAPI, Request

    from fastapi_spnego import SpnegoConfig, SpnegoMiddleware

    app = FastAPI()
    app.add_middleware(SpnegoMiddleware, config=SpnegoConfig(accept_any_principal=True))

    @app.get("/whoami")
    def whoami(request: Request) -> dict:
        identity = request.state.spnego_identity
        return {"principal": identity.principal, "username": identity.username}

    return app


def test_dependency_challenges_without_header(krb_realm: object) -> None:
    with TestClient(_dependency_app()) as client:
        r = client.get("/whoami")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "Negotiate"


def test_dependency_rejects_garbage_token(krb_realm: object) -> None:
    # A present-but-bogus token is a client error (403), never a 500.
    with TestClient(_dependency_app()) as client:
        r = client.get("/whoami", headers={"Authorization": "Negotiate bm90YXRva2Vu"})
    assert r.status_code == 403


def test_dependency_authenticates_real_ticket(krb_realm: object) -> None:
    # Default initiate flags request mutual authentication, so the server must
    # return a token; feeding it back completes the client context — proving the
    # WWW-Authenticate response leg is genuinely valid, not just present.
    client_ctx, token = _negotiate_token(krb_realm)
    with TestClient(_dependency_app()) as client:
        r = client.get("/whoami", headers={"Authorization": f"Negotiate {token}"})

    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "user"
    assert body["realm"] == krb_realm.realm
    assert body["principal"] == krb_realm.user_princ

    challenge = r.headers.get("WWW-Authenticate", "")
    assert challenge.startswith("Negotiate ")
    client_ctx.step(base64.b64decode(challenge.split(" ", 1)[1]))
    assert client_ctx.complete


def test_middleware_authenticates_real_ticket(krb_realm: object) -> None:
    # Mutual auth off: single-leg handshake, no return token needed.
    _, token = _negotiate_token(
        krb_realm, flags=[gssapi.RequirementFlag.out_of_sequence_detection]
    )
    with TestClient(_middleware_app()) as client:
        r = client.get("/whoami", headers={"Authorization": f"Negotiate {token}"})

    assert r.status_code == 200
    assert r.json()["username"] == "user"

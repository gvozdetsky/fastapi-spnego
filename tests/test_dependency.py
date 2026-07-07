"""Unit tests for the dependency's protocol handling (no real KDC needed).

These use a fake backend so we can assert the HTTP Negotiate state machine
without a Kerberos environment. The real end-to-end test against a containerized
KDC is tracked in PLAN.md step 3 and lives in test_integration.py (TODO).
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_spnego import SpnegoAuth, SpnegoIdentity
from fastapi_spnego.config import SpnegoConfig
from fastapi_spnego.exceptions import NegotiateFailedError
from fastapi_spnego.models import NegotiateResult


class FakeBackend:
    """Deterministic backend covering every branch of the state machine.

    - ``good``     → completes as alice@EXAMPLE.COM (with a mutual-auth token)
    - ``continue`` → asks for another leg
    - ``bad``      → raises NegotiateFailedError (invalid client token)
    - ``noidentity`` → misbehaves: reports complete but returns no identity
    """

    def step(self, in_token_b64: str) -> NegotiateResult:
        if in_token_b64 == "good":
            return NegotiateResult(
                complete=True,
                out_token="server-mutual",
                identity=SpnegoIdentity.from_principal("alice@EXAMPLE.COM"),
            )
        if in_token_b64 == "continue":
            return NegotiateResult(complete=False, out_token="more")
        if in_token_b64 == "noidentity":
            return NegotiateResult(complete=True, out_token=None, identity=None)
        raise NegotiateFailedError("bad token")


def make_app(auto_error: bool = True) -> FastAPI:
    app = FastAPI()
    auth = SpnegoAuth(backend=FakeBackend(), config=SpnegoConfig(auto_error=auto_error))

    @app.get("/whoami")
    def whoami(identity: SpnegoIdentity = Depends(auth)):  # type: ignore[no-untyped-def]
        return {"username": identity.username}

    return app


def test_missing_header_challenges() -> None:
    client = TestClient(make_app())
    r = client.get("/whoami")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Negotiate"


def test_valid_token_authenticates_and_returns_mutual_token() -> None:
    client = TestClient(make_app())
    r = client.get("/whoami", headers={"Authorization": "Negotiate good"})
    assert r.status_code == 200
    assert r.json() == {"username": "alice"}
    assert r.headers["WWW-Authenticate"] == "Negotiate server-mutual"


def test_continuation_leg_bounces_token() -> None:
    client = TestClient(make_app())
    r = client.get("/whoami", headers={"Authorization": "Negotiate continue"})
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Negotiate more"


@pytest.mark.parametrize("value", ["", "Basic abc", "Bearer xyz"])
def test_non_negotiate_header_challenges(value: str) -> None:
    client = TestClient(make_app())
    headers = {"Authorization": value} if value else {}
    r = client.get("/whoami", headers=headers)
    assert r.status_code == 401


def test_invalid_token_returns_403_not_500() -> None:
    # Regression: a bad client token must not crash the server with a 500.
    client = TestClient(make_app(), raise_server_exceptions=False)
    r = client.get("/whoami", headers={"Authorization": "Negotiate bad"})
    assert r.status_code == 403
    # A failed validation is terminal — no challenge to loop on.
    assert "WWW-Authenticate" not in r.headers


def test_invalid_token_optional_auth_returns_none() -> None:
    # With auto_error=False the route runs; identity resolves to None.
    app = FastAPI()
    auth = SpnegoAuth(backend=FakeBackend(), config=SpnegoConfig(auto_error=False))

    @app.get("/whoami")
    def whoami(identity: SpnegoIdentity | None = Depends(auth)):  # type: ignore[no-untyped-def]
        return {"authenticated": identity is not None}

    client = TestClient(app)
    r = client.get("/whoami", headers={"Authorization": "Negotiate bad"})
    assert r.status_code == 200
    assert r.json() == {"authenticated": False}


def test_complete_without_identity_fails_closed() -> None:
    # A misbehaving backend must not leak an unauthenticated request through.
    client = TestClient(make_app(), raise_server_exceptions=False)
    r = client.get("/whoami", headers={"Authorization": "Negotiate noidentity"})
    assert r.status_code == 403

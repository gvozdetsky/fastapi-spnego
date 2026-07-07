"""Unit tests for SpnegoMiddleware's ASGI-level Negotiate handling.

Like test_dependency.py, these use a fake backend so the HTTP state machine is
exercised without a Kerberos environment.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_spnego import SpnegoIdentity, SpnegoMiddleware
from fastapi_spnego.config import SpnegoConfig
from fastapi_spnego.exceptions import NegotiateFailedError
from fastapi_spnego.models import NegotiateResult


class FakeBackend:
    def step(self, in_token_b64: str) -> NegotiateResult:
        if in_token_b64 == "good":
            return NegotiateResult(
                complete=True,
                out_token="server-mutual",
                identity=SpnegoIdentity.from_principal("alice@EXAMPLE.COM"),
            )
        if in_token_b64 == "continue":
            return NegotiateResult(complete=False, out_token="more")
        raise NegotiateFailedError("bad token")


def make_app(auto_error: bool = True) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        SpnegoMiddleware,
        backend=FakeBackend(),
        config=SpnegoConfig(auto_error=auto_error),
        exclude_paths=["/health"],
    )

    @app.get("/whoami")
    def whoami(request: Request):  # type: ignore[no-untyped-def]
        identity = request.state.spnego_identity
        return {"username": identity.username if identity else None}

    @app.get("/health")
    def health():  # type: ignore[no-untyped-def]
        return {"status": "ok"}

    return app


def test_excluded_path_skips_auth() -> None:
    client = TestClient(make_app())
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_missing_header_challenges() -> None:
    client = TestClient(make_app())
    r = client.get("/whoami")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Negotiate"


def test_valid_token_sets_identity_and_mutual_token() -> None:
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


def test_invalid_token_returns_403() -> None:
    client = TestClient(make_app(), raise_server_exceptions=False)
    r = client.get("/whoami", headers={"Authorization": "Negotiate bad"})
    assert r.status_code == 403


def test_optional_auth_lets_request_through_without_identity() -> None:
    client = TestClient(make_app(auto_error=False))
    r = client.get("/whoami")
    assert r.status_code == 200
    assert r.json() == {"username": None}

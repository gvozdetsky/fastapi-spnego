"""End-to-end SPNEGO/Kerberos test against a real MIT KDC.

This is the proof that the GSSAPI accept path actually works — not a fake
backend, but a genuine Negotiate handshake: a client with a real TGT talks to
the app, which validates the token against its service keytab.

It only runs inside the Docker compose environment (see docker-compose.yml),
where `requests-gssapi`, the krb5 client tools, and a reachable KDC all exist::

    docker compose run --rm --build test

Outside that environment the module skips itself (no `requests-gssapi`), so the
normal unit-test run is unaffected.
"""

from __future__ import annotations

import os
import subprocess

import pytest

# Only meaningful with a Kerberos client stack + a live KDC (the Docker env).
requests = pytest.importorskip("requests")
requests_gssapi = pytest.importorskip("requests_gssapi")

pytestmark = pytest.mark.integration

REALM = "EXAMPLE.COM"
USER = f"alice@{REALM}"
PASSWORD = "alicepassword"
BASE_URL = os.environ.get("SPNEGO_TEST_URL", "http://app.example.com:8000")


def _kinit(forwardable: bool = False) -> None:
    """Obtain a fresh TGT for the test user via the client's password."""
    subprocess.run(["kdestroy"], check=False)
    cmd = ["kinit"]
    if forwardable:
        cmd.append("-f")
    cmd.append(USER)
    subprocess.run(cmd, input=f"{PASSWORD}\n".encode(), check=True)


@pytest.fixture
def tgt():
    _kinit()
    yield
    subprocess.run(["kdestroy"], check=False)


@pytest.fixture
def forwardable_tgt():
    _kinit(forwardable=True)
    yield
    subprocess.run(["kdestroy"], check=False)


def test_no_credentials_gets_negotiate_challenge() -> None:
    r = requests.get(f"{BASE_URL}/whoami", timeout=10)
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "Negotiate"


def test_health_is_unauthenticated() -> None:
    r = requests.get(f"{BASE_URL}/health", timeout=10)
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_authenticates_with_real_ticket(tgt: None) -> None:
    # Mutual auth REQUIRED: requests-gssapi verifies the server's return token,
    # so a green here also proves the WWW-Authenticate response leg is correct.
    auth = requests_gssapi.HTTPSPNEGOAuth(mutual_authentication=requests_gssapi.REQUIRED)
    r = requests.get(f"{BASE_URL}/whoami", auth=auth, timeout=10)

    assert r.status_code == 200
    body = r.json()
    assert body["principal"] == USER
    assert body["username"] == "alice"
    assert body["realm"] == REALM
    assert r.headers.get("WWW-Authenticate", "").startswith("Negotiate ")


def test_delegation_captures_ccache(forwardable_tgt: None) -> None:
    # Client forwards its TGT; the server (allow_delegation=true) must store it.
    auth = requests_gssapi.HTTPSPNEGOAuth(
        mutual_authentication=requests_gssapi.REQUIRED, delegate=True
    )
    r = requests.get(f"{BASE_URL}/whoami", auth=auth, timeout=10)

    assert r.status_code == 200
    body = r.json()
    assert body["delegated_ccache"], "expected delegated credentials to be captured"
    assert body["delegated_ccache"].startswith("FILE:")
    # ticket_lifetime() read the stored ccache back and found a live ticket.
    assert isinstance(body["ccache_lifetime"], int) and body["ccache_lifetime"] > 0

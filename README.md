# fastapi-spnego

**SPNEGO / Kerberos (HTTP `Negotiate`) authentication for FastAPI and Starlette.**

The one enterprise auth mechanism with no FastAPI library — until now. Where
`fastapi-ldap` covers LDAP and Authlib covers OAuth2/OIDC, Kerberos/SPNEGO users
have been told to bolt on Keycloak. This package fills that gap: a small,
framework-idiomatic `Negotiate` provider you drop in as a dependency.

> **Status: beta.** The dependency, the optional ASGI middleware, and
> credential delegation are implemented and covered by unit tests. The real
> GSSAPI path is proven end-to-end against a containerized MIT KDC
> (`docker compose run --rm test`) — genuine `kinit` + Negotiate handshake,
> mutual auth, and delegation.

## Install

```bash
pip install fastapi-spnego[gssapi]   # Linux/macOS; needs libkrb5-dev
```

**Platform support:** the server-side GSSAPI backend runs on **Linux and macOS**
(where FastAPI is almost always deployed). Windows clients authenticate normally
against it. The base package is pure-Python and imports anywhere; the
`gssapi` extra is what requires system Kerberos libraries.

## Use

```python
from fastapi import Depends, FastAPI
from fastapi_spnego import SpnegoAuth, SpnegoIdentity

app = FastAPI()
spnego = SpnegoAuth()

@app.get("/whoami")
def whoami(identity: SpnegoIdentity = Depends(spnego)):
    return {"user": identity.username, "realm": identity.realm}
```

Configure via `SPNEGO_` env vars (see `fastapi_spnego/config.py`):

```bash
export SPNEGO_HOSTNAME=app.example.com     # FQDN of the service principal
export SPNEGO_KEYTAB=/etc/app.keytab       # HTTP/app.example.com@REALM
export SPNEGO_ALLOW_DELEGATION=true        # capture forwarded client TGTs (optional)
export SPNEGO_ACCEPT_ANY_PRINCIPAL=true    # accept any SPN in the keytab (reverse proxies)
```

Deploying for real (keytab creation, browser SPNEGO allowlisting, reverse-proxy
notes, troubleshooting) is covered in **[docs/deploying.md](./docs/deploying.md)**.

A bad or missing token is handled for you: no credentials → `401` with a
`WWW-Authenticate: Negotiate` challenge; an invalid token → `403`.
Set `SPNEGO_AUTO_ERROR=false` for optional auth, where the dependency
returns `None` instead of challenging.

## Global middleware (alternative)

Prefer the `Depends()` above for most apps. If you'd rather apply Negotiate
globally and read the identity off `request.state` (Flask `before_request`
style), use the middleware:

```python
from fastapi import FastAPI, Request
from fastapi_spnego import SpnegoMiddleware

app = FastAPI()
app.add_middleware(SpnegoMiddleware, exclude_paths=["/health", "/metrics"])

@app.get("/whoami")
def whoami(request: Request):
    identity = request.state.spnego_identity
    return {"user": identity.username}
```

## Credential delegation

With `SPNEGO_ALLOW_DELEGATION=true`, when a client forwards (delegates) its TGT
the server stores it in a per-user credentials cache and exposes the handle on
the identity, so your app can act onward as that user:

```python
from fastapi_spnego import ticket_lifetime, cleanup

identity.delegated_ccache             # "FILE:/tmp/fastapi_spnego_ccache/cache_alice_EXAMPLE.COM"
ticket_lifetime(identity.delegated_ccache)   # remaining seconds, or None if gone/expired
# use it: env KRB5CCNAME=<handle> for an onward Kerberos connection
cleanup(identity.delegated_ccache)    # remove the ccache on logout/teardown
```

Re-authentication refreshes the ccache automatically. Requires the SPN to be
flagged *trusted for delegation* and the client to opt in (GSSAPI/SSPI-only; the
GSSAPI backend supports this, `pyspnego` will not).

## Design

- **A `Depends()`, not a global.** Fits FastAPI's DI model; trivial to override in tests.
- **Pluggable backend.** GSSAPI first (Linux/macOS, supports credential delegation);
  a `pyspnego` backend for Windows/SSPI is on the roadmap.
- **Non-blocking.** GSSAPI calls run in a threadpool.
- **Just a provider.** Returns a verified principal; your app owns users/sessions/RBAC.

## Development

This project uses [uv](https://docs.astral.sh/uv/) for environment and
dependency management.

```bash
uv sync                 # create .venv + install the base dev group
uv run pytest           # run the test suite
uv run ruff check .     # lint
uv run ruff format .    # format
uv run mypy fastapi_spnego
```

The base `dev` group is pure-Python and installs anywhere. To run the
integration tests that exercise the real GSSAPI backend you also need the
`gssapi` group, which requires system Kerberos headers (`krb5-config` on
`PATH`, e.g. `apt install libkrb5-dev`):

```bash
uv sync --group gssapi
```

`uv.lock` is committed for reproducible dev/CI environments. It does not affect
consumers, who install the published package via `pip` as usual.

### End-to-end test against a real KDC

The unit tests use a fake backend and need no Kerberos. The real proof — an
actual `kinit` + Negotiate handshake against the GSSAPI backend — runs in
Docker, which stands up a throwaway MIT KDC, the app, and a client:

```bash
docker compose run --rm --build test   # KDC + app + integration suite
docker compose up --build app           # or: just serve on localhost:8000
```

This exercises the challenge, a successful handshake with mutual auth, and
credential delegation. See `docker-compose.yml` and `docker/`.

## License

MIT.

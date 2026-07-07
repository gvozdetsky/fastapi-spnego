# Roadmap

Where `fastapi-spnego` is headed. Suggestions and contributions welcome — open an
issue to discuss.

## Shipped

**0.1.0** — first public release
- `SpnegoAuth` FastAPI dependency + optional `SpnegoMiddleware` (global Negotiate,
  identity on `request.state`).
- `GSSAPIBackend`: real Kerberos accept step, mutual authentication, and
  credential delegation captured to a per-user ccache.
- Robust HTTP semantics: `401` challenge when unauthenticated, `403` on an invalid
  token (never a `500`), optional (`auto_error=False`) mode.
- Proven end-to-end against a real MIT KDC in CI (`docker compose run --rm test`):
  `kinit` → Negotiate handshake → mutual auth → delegation.
- CI matrix on Python 3.10–3.13 (ruff, mypy, unit tests) + the KDC integration job.

## 0.2.0 — production-ready & documented

Solidify, type, and document what exists; close the delegation lifecycle.

- **Typing**: ship a `py.typed` marker (PEP 561) so downstream `mypy`/IDEs see the
  library's type hints.
- **Delegation lifecycle**:
  - `ticket_lifetime(handle)` — remaining lifetime of a stored delegated ccache.
  - Public, documented `cleanup(handle)` for logout/teardown.
  - Document that re-authentication automatically refreshes the ccache.
- **Reverse-proxy / multi-SPN**: optionally accept *any* principal present in the
  keytab (`GSS_C_NO_NAME`), fixing SPN mismatches behind nginx/other proxies.
- **User-facing docs**: service-keytab creation, browser SPNEGO allowlisting
  (Chrome/Firefox), reverse-proxy notes, and the delegation lifecycle.
- **Project health**: `CHANGELOG.md`, `CONTRIBUTING.md`, issue templates; test
  coverage reporting in CI.
- Graduate the package classifier from `Alpha` to `Beta`.

## 0.3.0 — integrate & harden

Make it production-grade on Linux/GSSAPI and idiomatic for Starlette apps.
(No Windows/SSPI backend — see *Not planned*.)

- **Starlette `AuthenticationBackend`.** Ship a backend so the verified principal
  lands on `request.user` / `request.auth` and composes with Starlette's
  `@requires(...)` scopes — a first-class option alongside the existing dependency
  and middleware. Makes the library idiomatic for the whole Starlette ecosystem.
- **Authenticate once, then session.** A helper (and recipe) to issue a signed
  session cookie after the first successful Negotiate, so browsers don't
  re-negotiate on every request. This is the standard real-world pattern
  (WebSphere LTPA, Hadoop's signed cookie, `mod_auth_gssapi`'s `GssapiUseSessions`)
  and the single biggest deployment-usability win.
- **Testing utilities** (`fastapi_spnego.testing`). A public fake backend + helpers
  so downstream apps can test their SPNEGO-protected routes without a KDC — a real
  adoption lever (today the fake backend only exists inside our own tests).
- **Channel binding / Extended Protection for Authentication** (opt-in). Bind the
  Negotiate token to the TLS `tls-server-end-point` certificate hash. Active
  Directory increasingly *enforces* this; `requests-kerberos` has done it
  client-side since 0.12. The wrinkle is getting the cert behind a TLS-terminating
  proxy — design carefully.
- **Require-HTTPS option.** Refuse Negotiate over plaintext, honouring
  `X-Forwarded-Proto` behind a reverse proxy (cf. `GssapiSSLonly`).
- **Authorization data (stretch).** Expose Kerberos PAC / name-attribute data
  (group SIDs) so apps can do group-based authz without a separate LDAP round trip
  (cf. `GssapiNameAttributes`) — or, to start, a documented LDAP-lookup recipe.


## Later / under consideration

- **Constrained delegation**: S4U2Proxy and S4U2Self / protocol transition for
  onward auth (cf. `mod_auth_gssapi` `GssapiUseS4U2Proxy` / `GssapiImpersonate`).
- **BasicAuth → GSSAPI fallback** for clients that can't do Negotiate.
- **Local name mapping** via `gss_localname` (`auth_to_local` rules).
- Stateful multi-leg negotiation (NTLM). Legacy and discouraged; low priority.

## Not planned

- **Windows / SSPI (`pyspnego`) server backend.** The server side targets
  Linux/macOS, where FastAPI is deployed; Windows *clients* already authenticate
  against it fine. Revisit only if there's real demand for running the app on
  Windows.

## Out of scope (by design)

`fastapi-spnego` is *one provider*: it verifies a client and returns a principal.
User storage, sessions, RBAC, and login UI belong to your application.

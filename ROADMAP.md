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

## 0.3.0 — cross-platform

- **`pyspnego` / SSPI backend** so the server side runs on **Windows**, with
  `default_backend()` preferring SSPI there and GSSAPI elsewhere.
- Windows CI runner exercising the SSPI path.

## Later / under consideration

- Stateful multi-leg negotiation (NTLM fallback). Low priority — NTLM is legacy and
  discouraged; Kerberos completes in a single leg.
- Pluggable identity mapping hooks (principal → app user) as optional helpers,
  without pulling user storage into scope.

## Out of scope (by design)

`fastapi-spnego` is *one provider*: it verifies a client and returns a principal.
User storage, sessions, RBAC, and login UI belong to your application.

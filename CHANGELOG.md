# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-07-07

### Added
- `py.typed` marker (PEP 561): downstream `mypy`/IDEs now see the library's inline
  type hints.
- `ticket_lifetime(handle)` — read the remaining lifetime of a stored delegated
  ccache. Exported from the package root alongside `store_delegated` and `cleanup`.
- `SpnegoConfig.accept_any_principal` (env `SPNEGO_ACCEPT_ANY_PRINCIPAL`): accept
  any service principal present in the keytab (`GSS_C_NO_NAME`) instead of pinning
  to a single SPN — robust behind reverse proxies and with multi-SPN keytabs.
- Deployment documentation: service-keytab creation, browser SPNEGO allowlisting,
  reverse-proxy notes, and the delegation lifecycle (`docs/deploying.md`).
- `CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`, and issue templates.

### Changed
- The package version is now derived from the Git tag via `setuptools_scm` — no
  version string is hardcoded. Tagging `vX.Y.Z` sets the release version.

## [0.1.0] — 2026-07-07

First public release.

### Added
- `SpnegoAuth` FastAPI dependency performing the HTTP `Negotiate` handshake.
- `SpnegoMiddleware`: optional ASGI middleware applying Negotiate globally and
  exposing the identity on `request.state.spnego_identity`, with a path allowlist.
- `GSSAPIBackend`: real Kerberos accept step, mutual authentication, and
  delegated-credential capture into a per-user ccache under `allow_delegation`.
- `SpnegoConfig` (env-prefixed `SPNEGO_`), `SpnegoIdentity`, and typed exceptions.
- Robust HTTP semantics: `401` + `WWW-Authenticate: Negotiate` when unauthenticated,
  `403` on an invalid token (never a `500`), and an optional (`auto_error=False`)
  mode returning `None`.
- End-to-end integration test against a real MIT KDC via Docker Compose.
- CI on Python 3.10–3.13 (ruff, mypy, unit tests) plus the KDC integration job.

[Unreleased]: https://github.com/gvozdetsky/fastapi-spnego/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gvozdetsky/fastapi-spnego/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gvozdetsky/fastapi-spnego/releases/tag/v0.1.0

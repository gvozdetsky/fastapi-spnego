# Contributing to fastapi-spnego

Thanks for your interest — issues and pull requests are welcome.

## Development setup

This project uses [uv](https://docs.astral.sh/uv/):

```bash
uv sync                        # base dev env (pure-Python, installs anywhere)
uv run pytest                  # unit tests (fake backend, no Kerberos needed)
uv run ruff check .            # lint
uv run ruff format .           # format
uv run mypy fastapi_spnego     # type-check
```

The unit tests need no Kerberos environment. The real end-to-end proof runs in
Docker against a throwaway MIT KDC:

```bash
docker compose run --rm --build test
```

## Before opening a PR

- `uv run ruff check .`, `uv run ruff format --check .`, and `uv run mypy
  fastapi_spnego` all pass.
- `uv run pytest` passes; add tests for new behavior.
- If you touch the GSSAPI accept path, run the Docker integration suite.
- Update `CHANGELOG.md` (under `## [Unreleased]`) and any relevant docs.

## Scope

fastapi-spnego is *one auth provider*: it verifies a client and returns a
principal. User storage, sessions, RBAC, and login UI are intentionally out of
scope — see [`ROADMAP.md`](./ROADMAP.md). Please open an issue to discuss larger
features (e.g. a new backend) before investing in a PR.

## Reporting security issues

Please do not open a public issue for a security vulnerability. Instead, report it
privately via the repository's security advisory page on GitHub.

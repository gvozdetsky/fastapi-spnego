"""Unit tests for delegated-credential ccache handling.

These use a fake credentials object that records the ``store()`` call, so the
filesystem/naming/permission logic is covered without a real GSSAPI context.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from fastapi_spnego.ccache import cleanup, store_delegated
from fastapi_spnego.config import SpnegoConfig


class FakeName:
    def __init__(self, value: str) -> None:
        self._value = value

    def __str__(self) -> str:
        return self._value


class FakeCreds:
    """Stand-in for gssapi.Credentials: records what store() was asked to do."""

    def __init__(self, name: str) -> None:
        self.name = FakeName(name)
        self.stored: dict | None = None

    def store(self, store: dict, overwrite: bool, set_default: bool) -> None:
        self.stored = store
        # Emulate gssapi actually creating the ccache file on disk.
        path = store["ccache"][len("FILE:") :]
        Path(path).write_bytes(b"fake-ccache")


def _config(tmp_path: Path) -> SpnegoConfig:
    return SpnegoConfig(ccache_dir=str(tmp_path / "cc"), allow_delegation=True)


def test_store_delegated_writes_ccache_and_returns_handle(tmp_path: Path) -> None:
    creds = FakeCreds("alice@EXAMPLE.COM")
    handle = store_delegated(creds, _config(tmp_path))

    assert handle is not None and handle.startswith("FILE:")
    path = handle[len("FILE:") :]
    assert os.path.exists(path)
    # Principal separators must be sanitised out of the filename.
    assert "@" not in os.path.basename(path)
    assert "/" not in os.path.basename(path)
    assert creds.stored == {"ccache": handle}


def test_store_delegated_sets_restrictive_permissions(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    handle = store_delegated(FakeCreds("bob@EXAMPLE.COM"), cfg)
    assert handle is not None
    path = handle[len("FILE:") :]

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(cfg.ccache_dir).st_mode) == 0o700


def test_store_delegated_none_returns_none(tmp_path: Path) -> None:
    assert store_delegated(None, _config(tmp_path)) is None


def test_store_delegated_creds_without_name_returns_none(tmp_path: Path) -> None:
    class NoName:
        pass

    assert store_delegated(NoName(), _config(tmp_path)) is None


def test_cleanup_removes_ccache(tmp_path: Path) -> None:
    handle = store_delegated(FakeCreds("carol@EXAMPLE.COM"), _config(tmp_path))
    assert handle is not None
    path = handle[len("FILE:") :]
    assert os.path.exists(path)

    cleanup(handle)
    assert not os.path.exists(path)


def test_cleanup_is_idempotent_and_safe_on_missing() -> None:
    cleanup(None)  # no error
    cleanup("FILE:/nonexistent/path/cache_x")  # no error

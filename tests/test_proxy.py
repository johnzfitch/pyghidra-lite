"""Tests for the stdio-to-HTTP proxy utilities."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pyghidra_lite.proxy import (
    _backend_url,
    _data_dir,
    _find_serve_executable,
    _is_backend_alive,
    _lock_path,
    _pid_path,
    _read_pid,
    _remove_pid,
    _write_pid,
)


class TestDataDir:

    def test_respects_xdg(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert _data_dir() == tmp_path / "pyghidra-lite"

    def test_default_fallback(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        expected = Path.home() / ".local" / "share" / "pyghidra-lite"
        assert _data_dir() == expected


class TestPidLifecycle:

    def test_write_read_remove(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        port = 19999
        pid = os.getpid()  # use our own pid (guaranteed alive)

        _write_pid(port, pid)
        assert _pid_path(port).exists()
        assert _read_pid(port) == pid

        _remove_pid(port)
        assert not _pid_path(port).exists()

    def test_read_pid_stale(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        port = 19998

        # Write a PID that definitely doesn't exist
        _write_pid(port, 2_000_000_000)
        assert _read_pid(port) is None
        assert not _pid_path(port).exists()  # cleaned up

    def test_read_pid_missing(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert _read_pid(19997) is None


class TestUrls:

    def test_backend_url(self):
        assert _backend_url("127.0.0.1", 19101) == "http://127.0.0.1:19101/mcp"

    def test_backend_url_custom(self):
        assert _backend_url("0.0.0.0", 8080) == "http://0.0.0.0:8080/mcp"


class TestPaths:

    def test_pid_path_format(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert _pid_path(19101) == tmp_path / "pyghidra-lite" / "backend-19101.pid"

    def test_lock_path_format(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert _lock_path(19101) == tmp_path / "pyghidra-lite" / "backend-19101.lock"


class TestFindExecutable:

    def test_finds_venv_binary(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        exe = bin_dir / "pyghidra-lite"
        exe.write_text("#!/bin/sh")
        monkeypatch.setattr("sys.prefix", str(tmp_path))
        assert _find_serve_executable() == str(exe)

    def test_falls_back_to_which(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr("sys.prefix", str(tmp_path))  # no bin/ dir
        with patch("shutil.which", return_value="/usr/bin/pyghidra-lite"):
            assert _find_serve_executable() == "/usr/bin/pyghidra-lite"

    def test_falls_back_to_bare_name(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr("sys.prefix", str(tmp_path))
        with patch("shutil.which", return_value=None):
            assert _find_serve_executable() == "pyghidra-lite"


class TestBackendAlive:

    def test_returns_false_when_unreachable(self):
        # Nothing listening on this port
        assert _is_backend_alive("127.0.0.1", 19199) is False

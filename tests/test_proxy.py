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


class TestStreamableConcurrencyPatch:
    """Regression: concurrent tool calls must not crash the proxy.

    The MCP SDK's StreamableHTTPTransport.post_writer spawned deferred tasks that
    all closed over the LAST loop iteration's request context, so a burst of
    parallel tool calls crossed contexts -- earlier requests were dropped and the
    last was sent repeatedly, tearing down the bridge and disconnecting every
    pyghidra-lite tool. proxy.py monkeypatches the fix at import time.
    """

    def test_patch_applied_and_idempotent(self):
        from mcp.client.streamable_http import StreamableHTTPTransport

        # Importing pyghidra_lite.proxy (done above) applies the patch.
        assert getattr(
            StreamableHTTPTransport.post_writer, "_pyghidra_lite_patched", False
        ) is True
        # Re-running the patcher must not stack or error.
        from pyghidra_lite.proxy import _patch_streamable_http_concurrency

        _patch_streamable_http_concurrency()
        assert getattr(
            StreamableHTTPTransport.post_writer, "_pyghidra_lite_patched", False
        ) is True

    def test_concurrent_requests_keep_their_own_context(self):
        import anyio
        from mcp.client.streamable_http import StreamableHTTPTransport
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCMessage, JSONRPCRequest

        handled: list[str] = []

        class FakeTransport:
            session_id = "s"

            def _is_initialized_notification(self, _m):
                return False

            async def _handle_post_request(self, ctx):
                # Yield first so every spawned task is scheduled before any
                # records -- this is what exposes the closure-capture bug.
                await anyio.sleep(0)
                handled.append(ctx.session_message.message.root.id)

            async def _handle_resumption_request(self, ctx):  # pragma: no cover
                await anyio.sleep(0)

        async def drive():
            send, recv = anyio.create_memory_object_stream(10)
            rsw, _rsw_r = anyio.create_memory_object_stream(10)
            wsend, _w = anyio.create_memory_object_stream(10)
            for rid in ("A", "B", "C"):
                msg = JSONRPCMessage(
                    JSONRPCRequest(jsonrpc="2.0", id=rid, method="tools/call")
                )
                await send.send(SessionMessage(msg))
            await send.aclose()
            async with anyio.create_task_group() as tg:
                await StreamableHTTPTransport.post_writer(
                    FakeTransport(),
                    client=None,
                    write_stream_reader=recv,
                    read_stream_writer=rsw,
                    write_stream=wsend,
                    start_get_stream=lambda: None,
                    tg=tg,
                )

        anyio.run(drive)
        # Every request handled exactly once, none crossed/dropped/duplicated.
        assert sorted(handled) == ["A", "B", "C"]

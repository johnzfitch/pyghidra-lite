"""Tests for the stdio-to-HTTP proxy utilities."""
from __future__ import annotations

import os
import sysconfig
from pathlib import Path
from unittest.mock import patch

import pytest

from pyghidra_lite.proxy import (
    _backend_url,
    _console_script,
    _data_dir,
    _find_serve_executable,
    _is_backend_alive,
    _lock_path,
    _pid_alive,
    _pid_path,
    _read_pid,
    _remove_pid,
    _terminate_pid,
    _try_lock_exclusive,
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
    """Integration: _find_serve_executable() resolves the console script via
    sysconfig.get_path('scripts') -- the authoritative, scheme/platform-aware
    location pip installs into -- rather than a hardcoded sys.prefix + 'bin'
    guess (the root cause of the original Windows auto-start miss).
    """

    def test_finds_console_script(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        # sysconfig is the source of truth for the scripts dir; lay the script out
        # with the current platform's name so this passes on POSIX and Windows.
        name = "pyghidra-lite.exe" if os.name == "nt" else "pyghidra-lite"
        (tmp_path / name).write_text("x")
        monkeypatch.setattr(
            sysconfig, "get_path", lambda n: str(tmp_path) if n == "scripts" else None
        )
        assert _find_serve_executable() == os.path.join(str(tmp_path), name)

    def test_falls_back_to_which(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        # scripts dir exists but holds no console script (e.g. run from source).
        monkeypatch.setattr(sysconfig, "get_path", lambda n: str(tmp_path))
        with patch("shutil.which", return_value="/usr/bin/pyghidra-lite"):
            assert _find_serve_executable() == "/usr/bin/pyghidra-lite"

    def test_falls_back_to_bare_name(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr(sysconfig, "get_path", lambda n: str(tmp_path))
        with patch("shutil.which", return_value=None):
            assert _find_serve_executable() == "pyghidra-lite"

    def test_handles_missing_scripts_path(self, monkeypatch: pytest.MonkeyPatch):
        # sysconfig can return None for an unusual scheme -- must not crash.
        monkeypatch.setattr(sysconfig, "get_path", lambda n: None)
        with patch("shutil.which", return_value=None):
            assert _find_serve_executable() == "pyghidra-lite"


class TestConsoleScript:
    """Pure resolver -- both POSIX and Windows (.exe) branches exercised on any
    host by passing the platform flag explicitly. Patching the global os.name
    instead would corrupt pathlib's flavour and crash tmp_path cleanup.
    """

    def test_windows_finds_exe(self, tmp_path: Path):
        (tmp_path / "pyghidra-lite.exe").write_text("MZ")
        expected = os.path.join(str(tmp_path), "pyghidra-lite.exe")
        assert _console_script(str(tmp_path), windows=True) == expected

    def test_posix_finds_name(self, tmp_path: Path):
        (tmp_path / "pyghidra-lite").write_text("#!/bin/sh")
        expected = os.path.join(str(tmp_path), "pyghidra-lite")
        assert _console_script(str(tmp_path), windows=False) == expected

    def test_windows_ignores_posix_name(self, tmp_path: Path):
        # The extensionless POSIX name must NOT satisfy the Windows lookup.
        (tmp_path / "pyghidra-lite").write_text("#!/bin/sh")
        assert _console_script(str(tmp_path), windows=True) is None

    def test_posix_ignores_windows_exe(self, tmp_path: Path):
        (tmp_path / "pyghidra-lite.exe").write_text("MZ")
        assert _console_script(str(tmp_path), windows=False) is None

    def test_none_scripts_dir_returns_none(self):
        assert _console_script(None, windows=True) is None
        assert _console_script(None, windows=False) is None

    def test_missing_returns_none(self, tmp_path: Path):
        assert _console_script(str(tmp_path), windows=True) is None
        assert _console_script(str(tmp_path), windows=False) is None


class TestBackendAlive:

    def test_returns_false_when_unreachable(self):
        # Nothing listening on this port
        assert _is_backend_alive("127.0.0.1", 19199) is False


class TestPortIsFree:
    """Port-availability check that gates autostart (see _autostart_backend)."""

    def test_free_when_nothing_listening(self):
        from pyghidra_lite.proxy import _port_is_free

        assert _port_is_free("127.0.0.1", 19199) is True

    def test_occupied_when_socket_bound(self):
        import socket

        from pyghidra_lite.proxy import _port_is_free

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            assert _port_is_free("127.0.0.1", port) is False
        finally:
            srv.close()
        # Freed once the listener is closed.
        assert _port_is_free("127.0.0.1", port) is True


class TestAutostartNoDuplicate:
    """Regression: a busy-but-bound backend must NOT trigger a duplicate spawn.

    Reproduces the incident where a backend saturated by analysis failed the HTTP
    health check while still holding its port, so the proxy autostarted a second
    serve that raced for a port it could never bind -- leaving orphaned zombies.
    """

    def test_does_not_spawn_when_port_occupied(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        import pyghidra_lite.proxy as proxy

        monkeypatch.setattr(proxy, "_lock_path", lambda port: tmp_path / f"{port}.lock")
        # Port is occupied (busy backend) and health is initially failing, then the
        # backend answers on the next poll -- autostart should wait, never spawn.
        monkeypatch.setattr(proxy, "_port_is_free", lambda *a: False)
        alive = iter([False, True])  # re-check fails; wait-loop then succeeds
        monkeypatch.setattr(proxy, "_is_backend_alive", lambda *a: next(alive))
        monkeypatch.setattr(proxy, "AUTOSTART_POLL_INTERVAL", 0.0)

        spawned = []
        monkeypatch.setattr(
            proxy.subprocess, "Popen",
            lambda *a, **k: spawned.append(a) or pytest.fail("spawned a duplicate backend"),
        )

        proxy._autostart_backend("127.0.0.1", 19111)
        assert spawned == []


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


class TestPidAlive:
    """Cross-platform liveness. Critically NOT os.kill(pid, 0): on Windows that
    routes to TerminateProcess and would kill the process being probed.
    """

    def test_alive_for_self(self):
        assert _pid_alive(os.getpid()) is True

    def test_dead_for_unused_pid(self):
        assert _pid_alive(2_000_000_000) is False


class TestExclusiveLock:
    """_try_lock_exclusive serializes concurrent proxy starts (fcntl on POSIX,
    msvcrt on Windows). The lock is released when the file handle closes.
    """

    def test_contended_then_free_after_close(self, tmp_path: Path):
        p = tmp_path / "x.lock"
        with open(p, "w") as f1:
            assert _try_lock_exclusive(f1) is True
            with open(p, "w") as f2:
                # Held by f1 (a separate open-file description) -> contender fails.
                assert _try_lock_exclusive(f2) is False
        # Freed once f1 is closed.
        with open(p, "w") as f3:
            assert _try_lock_exclusive(f3) is True


class TestTerminatePid:
    """_terminate_pid must stop a real child without referencing signal.SIGKILL
    at import time (it does not exist on Windows).
    """

    def test_terminates_child(self):
        import subprocess
        import sys
        import time

        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            assert _pid_alive(proc.pid) is True
            _terminate_pid(proc.pid, force=False)
            for _ in range(60):
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
            assert proc.poll() is not None
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()

"""Lightweight stdio-to-HTTP proxy for shared pyghidra-lite backend.

Bridges MCP JSON-RPC over stdio to a persistent streamable-http backend,
so each Claude Code session uses ~10MB instead of ~500MB for its own JVM.
"""

from __future__ import annotations

import fcntl
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import anyio
import httpx

from mcp.client.streamable_http import streamable_http_client
from mcp.server.stdio import stdio_server

logger = logging.getLogger("pyghidra-lite-proxy")


def _patch_streamable_http_concurrency() -> None:
    """Fix an upstream MCP-SDK bug that crashes the proxy on concurrent tool calls.

    ``StreamableHTTPTransport.post_writer`` spawns one task per in-flight request
    via ``tg.start_soon(handle_request_async)``, but ``handle_request_async`` closes
    over the loop variables ``ctx`` and ``is_resumption`` *by reference*. Because
    ``start_soon`` defers execution, every queued task ends up reading the LAST
    iteration's ``ctx`` once a burst of requests is buffered: earlier requests are
    never POSTed (their callers hang) and the latest request is POSTed N times. The
    resulting duplicate-id / missing-response traffic tears down the SSE stream,
    which closes the proxy's bridge streams and kills the whole proxy process --
    Claude Code then loses ALL pyghidra-lite tools until a manual /mcp reconnect.

    Confirmed present in mcp 1.26.0 through 1.28.0 (latest); no released fix. We
    replace the method with an identical copy whose inner coroutine binds ``ctx``
    and ``is_resumption`` as default arguments (per-iteration capture). The patch is
    self-deactivating: if a future SDK no longer ships the buggy pattern we leave it
    untouched, and it is idempotent across repeated imports.
    """
    import inspect

    from mcp.client.streamable_http import (
        ClientMessageMetadata,
        JSONRPCRequest,
        RequestContext,
        StreamableHTTPTransport,
    )

    if getattr(StreamableHTTPTransport.post_writer, "_pyghidra_lite_patched", False):
        return
    try:
        src = inspect.getsource(StreamableHTTPTransport.post_writer)
    except (OSError, TypeError):
        src = ""
    # Only patch the known-buggy shape; a fixed upstream method is left alone.
    if "tg.start_soon(handle_request_async)" not in src or "ctx=ctx" in src:
        return

    async def post_writer(
        self,
        client,
        write_stream_reader,
        read_stream_writer,
        write_stream,
        start_get_stream,
        tg,
    ):
        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    message = session_message.message
                    metadata = (
                        session_message.metadata
                        if isinstance(session_message.metadata, ClientMessageMetadata)
                        else None
                    )
                    is_resumption = bool(metadata and metadata.resumption_token)
                    if self._is_initialized_notification(message):
                        start_get_stream()
                    ctx = RequestContext(
                        client=client,
                        session_id=self.session_id,
                        session_message=session_message,
                        metadata=metadata,
                        read_stream_writer=read_stream_writer,
                    )

                    # FIX: bind ctx + is_resumption as defaults so each deferred
                    # task captures ITS OWN request, not the final loop values.
                    async def handle_request_async(ctx=ctx, is_resumption=is_resumption):
                        if is_resumption:
                            await self._handle_resumption_request(ctx)
                        else:
                            await self._handle_post_request(ctx)

                    if isinstance(message.root, JSONRPCRequest):
                        tg.start_soon(handle_request_async)
                    else:
                        await handle_request_async()
        except Exception:
            logger.exception("Error in patched post_writer")
        finally:
            await read_stream_writer.aclose()
            await write_stream.aclose()

    post_writer._pyghidra_lite_patched = True
    StreamableHTTPTransport.post_writer = post_writer
    logger.info("Applied streamable-http concurrency fix (upstream closure bug).")


_patch_streamable_http_concurrency()

DEFAULT_PORT = 19101
DEFAULT_HOST = "127.0.0.1"
HEALTH_TIMEOUT = 2.0
AUTOSTART_POLL_INTERVAL = 0.5
AUTOSTART_POLL_TIMEOUT = 15.0


def _data_dir() -> Path:
    """XDG-compliant data directory for pyghidra-lite."""
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "pyghidra-lite"


def _pid_path(port: int) -> Path:
    return _data_dir() / f"backend-{port}.pid"


def _lock_path(port: int) -> Path:
    return _data_dir() / f"backend-{port}.lock"


def _write_pid(port: int, pid: int) -> None:
    path = _pid_path(port)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid))


def _read_pid(port: int) -> int | None:
    path = _pid_path(port)
    if not path.exists():
        return None
    try:
        pid = int(path.read_text().strip())
        os.kill(pid, 0)  # check if process is alive
        return pid
    except (ValueError, ProcessLookupError, OSError):
        path.unlink(missing_ok=True)
        return None


def _remove_pid(port: int) -> None:
    _pid_path(port).unlink(missing_ok=True)


def stop_backend(port: int = DEFAULT_PORT) -> bool:
    """Stop a running backend by PID file. Returns True if stopped."""
    pid = _read_pid(port)
    if pid is None:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.25)
            try:
                os.kill(pid, 0)
            except OSError:
                _remove_pid(port)
                return True
        os.kill(pid, signal.SIGKILL)
        _remove_pid(port)
        return True
    except OSError:
        _remove_pid(port)
        return False


def _backend_url(host: str, port: int) -> str:
    return f"http://{host}:{port}/mcp"


def _is_backend_alive(host: str, port: int) -> bool:
    """Check if the backend is reachable via HTTP."""
    try:
        resp = httpx.get(
            _backend_url(host, port),
            timeout=HEALTH_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        return resp.status_code < 500
    except (httpx.ConnectError, httpx.TimeoutException):
        return False


def _autostart_backend(host: str, port: int) -> None:
    """Spawn the backend as a detached process and wait for it to be ready.

    Uses an exclusive file lock to prevent concurrent proxy starts from
    spawning multiple backends on the same port.
    """
    lock_file_path = _lock_path(port)
    lock_file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(lock_file_path, "w") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another proxy is already starting the backend -- wait for it
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            # By the time we get the lock, backend should be up
            if _is_backend_alive(host, port):
                return
            # Other starter failed -- fall through and try ourselves

        # Re-check after acquiring lock (another process may have started it)
        if _is_backend_alive(host, port):
            return

        _read_pid(port)  # clean stale PID entries

        exe = _find_serve_executable()
        cmd = [
            exe, "serve",
            "--transport", "streamable-http",
            "--port", str(port),
            "--host", host,
            "--idle-timeout", "30",
        ]
        logger.info("Auto-starting backend on port %d", port)

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _write_pid(port, proc.pid)

        deadline = time.monotonic() + AUTOSTART_POLL_TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(AUTOSTART_POLL_INTERVAL)
            if _is_backend_alive(host, port):
                logger.info("Backend is ready on port %d (pid %d)", port, proc.pid)
                return

        # Timed out -- kill the orphaned process
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        _remove_pid(port)
        logger.error("Backend did not start within %.0fs", AUTOSTART_POLL_TIMEOUT)
        sys.exit(1)


def _find_serve_executable() -> str:
    """Find the pyghidra-lite executable for auto-start."""
    # sys.prefix points to the venv root when installed
    candidate = os.path.join(sys.prefix, "bin", "pyghidra-lite")
    if os.path.isfile(candidate):
        return candidate
    return shutil.which("pyghidra-lite") or "pyghidra-lite"


async def run_proxy(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Bridge stdio <-> streamable-http backend."""
    no_autostart = os.environ.get("PYGHIDRA_LITE_NO_AUTOSTART", "").strip() == "1"

    if not _is_backend_alive(host, port):
        if no_autostart:
            logger.error("Backend not reachable at %s:%d and auto-start disabled", host, port)
            sys.exit(1)
        _autostart_backend(host, port)

    url = _backend_url(host, port)

    async with (
        stdio_server() as (stdio_read, stdio_write),
        streamable_http_client(url, terminate_on_close=False) as (
            http_read, http_write, _get_session_id,
        ),
    ):

        async def stdio_to_http():
            """Forward messages from stdin to the HTTP backend."""
            try:
                async for msg in stdio_read:
                    if isinstance(msg, Exception):
                        logger.warning("Bad message from stdin: %s", msg)
                        continue
                    await http_write.send(msg)
            except (anyio.ClosedResourceError, anyio.BrokenResourceError) as exc:
                logger.error("Backend connection lost: %s", exc)

        async def http_to_stdio():
            """Forward messages from the HTTP backend to stdout."""
            try:
                async for msg in http_read:
                    if isinstance(msg, Exception):
                        logger.warning("Bad message from backend: %s", msg)
                        continue
                    await stdio_write.send(msg)
            except (anyio.ClosedResourceError, anyio.BrokenResourceError) as exc:
                logger.error("Client disconnected: %s", exc)

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdio_to_http)
            tg.start_soon(http_to_stdio)

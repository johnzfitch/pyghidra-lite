# Fix pyghidra-lite server reliability issues

## Context

The proxy+backend architecture has reliability gaps around session recovery, lock contention, process identity validation, and shutdown cleanup. These were found during a manual audit of `proxy.py` and `server.py`. The goal is to harden the server for long-running sessions where the backend may restart (idle timeout, crash, manual stop) while proxies remain connected.

## Issue 1: Backend session recovery in proxy (Medium)

**Problem:** When the backend restarts, the MCP session is invalidated. The `streamable_http_client` holds a session ID that the new backend doesn't recognize. The proxy's forwarding loops catch `ClosedResourceError`/`BrokenResourceError` and log them, but then the proxy dies — the client gets no useful error and must restart Claude Code's MCP connection.

The real issue is **session invalidation**, not connection pooling. A new `streamable_http_client` context gets a fresh transport, but the MCP protocol requires an `initialize` handshake before any tools work. The stdio client (Claude Code) already sent `initialize` once and won't re-send it.

**Fix:** Transparent reconnect with init replay.

1. Cache the `initialize` request and `notifications/initialized` notification as they flow through the proxy on first connection
2. On backend disconnect, exit the `streamable_http_client` context
3. Auto-start backend if needed (reuse existing `_autostart_backend`)
4. Create a new `streamable_http_client` context
5. Replay the cached `initialize` request, wait for the response (discard it — stdio client already got one)
6. Replay the cached `initialized` notification
7. Resume forwarding — subsequent tool calls from stdio work on the new session
8. In-flight requests during the disconnect get JSON-RPC error responses forwarded back to stdio
9. Limit reconnect attempts (3) with linear backoff to avoid infinite loops

**File:** `src/pyghidra_lite/proxy.py`

Key changes to `run_proxy()`:
- Move `stdio_server()` outside the reconnect loop (stdio stays open)
- Wrap `streamable_http_client` in a retry loop
- Add message interception in `stdio_to_http` to cache init messages
- Add `_replay_init()` helper that sends cached init to the new backend and waits for the response
- Forwarding functions re-raise connection errors instead of swallowing them

```python
async def run_proxy(host, port):
    # Initial backend check + autostart (existing)
    ...
    url = _backend_url(host, port)
    cached_init_request = None    # SessionMessage
    cached_init_notification = None  # SessionMessage

    async with stdio_server() as (stdio_read, stdio_write):
        for attempt in range(MAX_RECONNECTS + 1):
            if attempt > 0:
                # Re-check/restart backend
                if not _is_backend_alive(host, port):
                    _autostart_backend(host, port)
                await anyio.sleep(min(attempt, 3))

            try:
                async with streamable_http_client(url, terminate_on_close=False) as (
                    http_read, http_write, _get_session_id
                ):
                    # Replay cached init on reconnect
                    if attempt > 0 and cached_init_request:
                        await _replay_init(http_write, http_read,
                                           cached_init_request,
                                           cached_init_notification)

                    async def stdio_to_http():
                        nonlocal cached_init_request, cached_init_notification
                        async for msg in stdio_read:
                            # Cache init messages on first pass
                            if cached_init_request is None:
                                ... # intercept and cache
                            await http_write.send(msg)

                    async def http_to_stdio():
                        async for msg in http_read:
                            await stdio_write.send(msg)

                    async with anyio.create_task_group() as tg:
                        tg.start_soon(stdio_to_http)
                        tg.start_soon(http_to_stdio)
                    return  # Clean exit
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                logger.warning("Backend connection lost (attempt %d/%d)",
                               attempt + 1, MAX_RECONNECTS + 1)
                continue

        logger.error("Backend connection lost after %d attempts", MAX_RECONNECTS + 1)
        sys.exit(1)
```

The `_replay_init()` helper sends the cached initialize request with a fresh request ID, reads the response (to complete the handshake), then sends the initialized notification. The response is discarded since the stdio client already has its init response from the original connection.

Message interception checks `isinstance(msg.message.root, JSONRPCRequest)` and `msg.message.root.method == "initialize"` to identify the init request, and similarly for the initialized notification.

## Issue 2: Lock contention — snapshot-and-release (Low-Medium)

**Problem:** `_with_handle()` holds `_backend_lock` during entire JVM operations. Three tools use it (`info`, `functions`, `code`), plus `xrefs` holds the lock explicitly. Meanwhile `search()` doesn't hold the lock at all.

The lock protects `_backend` and `backend.programs`, which are only mutated during init/close/import/delete. Read-only tool operations just need a stable handle reference.

**Fix:** Snapshot-and-release — hold `_backend_lock` only for handle lookup, release before JVM calls. Same pattern `search()` already uses. No per-binary decompile serialization needed (concurrent decompile on same binary is not a real scenario — one Claude session = one request at a time).

**File:** `src/pyghidra_lite/server.py`

### `_with_handle()` (line 834)

```python
# Before:
def _with_handle(action: str, binary: str, op):
    with _backend_lock:
        return _guarded_tool_call(action, lambda: op(_get_handle(binary)))

# After:
def _with_handle(action: str, binary: str, op):
    with _backend_lock:
        handle = _get_handle(binary)
    return _guarded_tool_call(action, lambda: op(handle))
```

### `xrefs()` (line 2684-2805)

Currently defines `op()` as a closure that calls `_get_handle(binary)` internally, then wraps the whole thing in `_backend_lock`. Refactor to use `_with_handle()` instead:

```python
# Before (line 2804-2805):
    with _backend_lock:
        return _guarded_tool_call("xrefs", op)

# After: extract handle lookup, pass to op
    with _backend_lock:
        handle = _get_handle(binary)
    tools = GhidraTools(handle)
    caps = _ensure_capabilities(handle)
    # ... rest of op logic using handle/tools/caps directly ...
```

This requires inlining the handle-dependent parts of xrefs' `op()` closure rather than wrapping it. The closure currently calls `_get_handle(binary)`, `GhidraTools(handle)`, and `_ensure_capabilities(handle)` internally.

### `_ensure_capabilities()` (line 805-811)

Double-check-lock pattern to avoid holding lock during `detect_capabilities()`:

```python
def _ensure_capabilities(handle) -> BinaryCapabilities:
    with _backend_lock:
        caps = _capabilities.get(handle.unit_id)
    if caps:
        return caps
    new_caps = detect_capabilities(handle)
    with _backend_lock:
        existing = _capabilities.get(handle.unit_id)
        if existing:
            return existing
        _capabilities[handle.unit_id] = new_caps
    return new_caps
```

## Issue 3: PID validation (Medium)

**Problem:** `_read_pid()` uses `os.kill(pid, 0)` to check liveness but doesn't verify the process is actually a pyghidra-lite backend. Recycled PIDs after reboot could match unrelated processes, causing `stop_backend()` to SIGTERM a random process.

**Fix:** Validate `/proc/{pid}/cmdline` contains "pyghidra" after the kill-0 check. Degrades gracefully on non-Linux (the `/proc` read fails, falls back to existing behavior).

**File:** `src/pyghidra_lite/proxy.py` — `_read_pid()` (line 55)

```python
def _read_pid(port: int) -> int | None:
    path = _pid_path(port)
    if not path.exists():
        return None
    try:
        pid = int(path.read_text().strip())
        os.kill(pid, 0)
        # Verify it's actually our backend, not a recycled PID
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
            if "pyghidra" not in cmdline:
                path.unlink(missing_ok=True)
                return None
        except OSError:
            pass  # /proc not available (non-Linux) — trust kill(0)
        return pid
    except (ValueError, ProcessLookupError, OSError):
        path.unlink(missing_ok=True)
        return None
```

## Issue 4: Worker + lock file cleanup on shutdown (Medium)

**Problem:** Worker subprocesses (`_run_analysis_worker`) tracked in `_active_jobs` aren't killed on server shutdown. Lock files at `~/.local/share/pyghidra-lite/backend-{port}.lock` are never explicitly removed.

**Fix:**

### Worker cleanup in `server_lifespan()` (line 1046)

Add worker SIGTERM before backend close in the finally block:

```python
finally:
    stale_task.cancel()
    # Kill active worker subprocesses
    for job in list(_active_jobs.values()):
        pid = job.get("pid")
        if pid and job.get("status") in ("queued", "running"):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    _active_jobs.clear()

    if observer:
        observer.stop()
        observer.join(timeout=2)
    with _backend_lock:
        if _backend:
            _backend.close()
            _backend = None
        _capabilities.clear()
```

### Lock file cleanup in `stop_backend()` (line 72)

```python
def stop_backend(port: int = DEFAULT_PORT) -> bool:
    # ... existing stop logic ...
    # After successful stop, clean up lock file:
    _lock_path(port).unlink(missing_ok=True)
    return True
```

## Files to modify

1. **`src/pyghidra_lite/proxy.py`** — session recovery with init replay, PID validation, lock file cleanup
2. **`src/pyghidra_lite/server.py`** — lock scope reduction (`_with_handle`, `xrefs`, `_ensure_capabilities`), worker cleanup on shutdown

## Verification

1. **Session recovery:** Start backend, start proxy, stop backend (`pyghidra-lite stop`), send MCP request — proxy should auto-restart backend and replay init
2. **Lock contention:** Load a binary, concurrent `info` + `functions` + `search` calls should not serialize (verify via timing or debug logging)
3. **PID validation:** Write a fake PID file pointing to an unrelated PID (e.g., a sleep process), verify `_read_pid` returns None
4. **Worker cleanup:** Start an analysis job, kill the server, verify worker subprocess is also terminated
5. **Existing tests:** `PYTHONPATH=src uv run pytest -q` — all existing tests pass unchanged

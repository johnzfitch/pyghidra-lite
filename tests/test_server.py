import asyncio
import os
from pathlib import Path

import pytest
from mcp import types

from pyghidra_lite import server


def test_resolve_import_path_unrestricted_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = server.ServerConfig()
    monkeypatch.setattr(server, "_server_config", config)
    target = tmp_path / "sample.bin"

    resolved = server._resolve_import_path(str(target))
    assert resolved == target.resolve()


def test_resolve_import_path_allows_restricted_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "sample.bin"
    config = server.ServerConfig(restrict_paths=[root])
    monkeypatch.setattr(server, "_server_config", config)

    resolved = server._resolve_import_path(str(target))
    assert resolved == target.resolve()


def test_resolve_import_path_blocks_outside_restricted_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "other.bin"
    config = server.ServerConfig(restrict_paths=[root])
    monkeypatch.setattr(server, "_server_config", config)

    with pytest.raises(ValueError):
        server._resolve_import_path(str(target))


def test_resolve_import_path_reports_symlink_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    target = outside / "target.bin"
    target.touch()
    link = root / "link.bin"
    link.symlink_to(target)
    config = server.ServerConfig(restrict_paths=[root])
    monkeypatch.setattr(server, "_server_config", config)

    with pytest.raises(ValueError) as exc:
        server._resolve_import_path(str(link))

    msg = str(exc.value)
    assert "requested=" in msg
    assert "resolves_to=" in msg
    assert str(link.resolve()) in msg


def test_ensure_runtime_environment_sets_user_home_and_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("JAVA_TOOL_OPTIONS", raising=False)
    monkeypatch.delenv("_JAVA_OPTIONS", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)

    runtime_home = tmp_path / "runtime"
    result = server._ensure_runtime_environment(tmp_path, runtime_home)

    assert result == runtime_home.resolve()
    assert os.environ["XDG_CONFIG_HOME"] == str((runtime_home / ".config").resolve())
    assert os.environ["XDG_CACHE_HOME"] == str((runtime_home / ".cache").resolve())
    assert f"-Duser.home={runtime_home.resolve()}" in os.environ["JAVA_TOOL_OPTIONS"]
    assert f"-Duser.home={runtime_home.resolve()}" in os.environ["_JAVA_OPTIONS"]


def test_upsert_jvm_option_preserves_existing_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("_JAVA_OPTIONS", "-Duser.home=/tmp/runtime -Xms256m")
    server._upsert_jvm_option("_JAVA_OPTIONS", "-Xmx", "-Xmx4g")
    opts = os.environ["_JAVA_OPTIONS"]
    assert "-Duser.home=/tmp/runtime" in opts
    assert "-Xms256m" in opts
    assert "-Xmx4g" in opts


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("::1", True),
        ("[::1]", True),
        ("127.0.0.2", True),  # all of 127.0.0.0/8 is loopback
        ("0.0.0.0", False),
        ("::", False),
        ("10.0.0.5", False),
        ("example.com", False),
    ],
)
def test_is_loopback_host(host: str, expected: bool) -> None:
    assert server._is_loopback_host(host) is expected


def test_build_transport_security_allows_localhost_and_bind_host() -> None:
    ts = server._build_transport_security("0.0.0.0", 9000, ("proxy.internal:9000",))
    assert ts.enable_dns_rebinding_protection is True
    assert "localhost:9000" in ts.allowed_hosts
    assert "127.0.0.1:9000" in ts.allowed_hosts
    assert "proxy.internal:9000" in ts.allowed_hosts
    assert "http://localhost:9000" in ts.allowed_origins
    # Wildcard bind itself is never an allowed Host header value.
    assert "0.0.0.0:9000" not in ts.allowed_hosts


def _drive_asgi(app, headers: list[tuple[bytes, bytes]]):
    """Invoke an ASGI app once with an http scope, capturing the response start."""
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = server._BearerAuthMiddleware(downstream, "s3cret")
    scope = {"type": "http", "headers": headers}
    asyncio.run(middleware(scope, receive, send))
    return sent


def test_bearer_auth_rejects_missing_token() -> None:
    sent = _drive_asgi(None, headers=[])
    assert sent[0]["status"] == 401


def test_bearer_auth_rejects_wrong_token() -> None:
    sent = _drive_asgi(None, headers=[(b"authorization", b"Bearer nope")])
    assert sent[0]["status"] == 401


def test_bearer_auth_accepts_correct_token() -> None:
    sent = _drive_asgi(None, headers=[(b"authorization", b"Bearer s3cret")])
    assert sent[0]["status"] == 200


def test_unit_id_for_caches_until_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unit_id is cached by (path, mtime, size) and recomputed when content changes."""
    monkeypatch.setattr(server, "_unit_id_cache", {})
    calls = {"n": 0}

    def fake_hash(p):
        calls["n"] += 1
        return f"{calls['n']:016x}"

    monkeypatch.setattr(server, "compute_unit_id_streaming", fake_hash)

    f = tmp_path / "bin"
    f.write_bytes(b"abc")
    first = server._unit_id_for(f)
    second = server._unit_id_for(f)
    assert first == second
    assert calls["n"] == 1  # second call served from cache

    # Changing size (and mtime) busts the cache.
    f.write_bytes(b"abcd")
    third = server._unit_id_for(f)
    assert calls["n"] == 2
    assert third != first


def test_guarded_tool_call_preserves_validation_errors() -> None:
    def op():
        raise ValueError("bad")

    with pytest.raises(ValueError, match="bad"):
        server._guarded_tool_call("test", op)


def test_guarded_tool_call_redacts_paths_in_generic_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unexpected exceptions must not leak absolute server paths to clients."""
    project_dir = tmp_path / "projects"
    monkeypatch.setattr(server, "_server_config", server.ServerConfig(project_dir=project_dir))

    leaky = str(project_dir / "abcdef0123456789" / "secret.gpr")

    def op():
        raise KeyError(f"boom at {leaky}")

    with pytest.raises(RuntimeError) as exc:
        server._guarded_tool_call("decompile", op)

    msg = str(exc.value)
    assert str(project_dir) not in msg
    assert "<project-dir>" in msg


def test_sanitize_redacts_relative_project_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative --project-dir must still redact the absolute paths in errors."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(server, "_server_config", server.ServerConfig(project_dir=Path("./projects")))

    abs_leak = str((tmp_path / "projects" / "abcdef0123456789").resolve())
    out = server._sanitize_error_text(f"boom at {abs_leak}/p.gpr")

    assert abs_leak not in out
    assert "<project-dir>" in out


def test_locked_tools_serializes_same_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    """_locked_tools holds the per-handle lock while the JVM work runs, so
    concurrent ops on the SAME binary serialize. (Different binaries get distinct
    locks and run concurrently -- asserted at the end.)"""
    import threading

    monkeypatch.setattr(server, "_tools_for", lambda h: "TOOLS")
    captured: dict = {}

    class _Handle:  # writable __dict__ so it gets a real per-handle lock
        pass

    handle = _Handle()
    hlock = server._handle_lock(handle)

    def work(tools):
        captured["tools"] = tools
        # Another thread must NOT be able to grab THIS handle's lock while held.
        result: dict = {}

        def other():
            result["got"] = hlock.acquire(blocking=False)
            if result["got"]:
                hlock.release()

        t = threading.Thread(target=other)
        t.start()
        t.join()
        captured["other_got_lock"] = result["got"]
        return "RESULT"

    out = server._locked_tools(handle, work)
    assert out == "RESULT"
    assert captured["tools"] == "TOOLS"
    assert captured["other_got_lock"] is False
    # A different handle is locked independently -> cross-binary concurrency.
    assert server._handle_lock(_Handle()) is not hlock


def test_assert_within_restrict_roots_rejects_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.touch()
    monkeypatch.setattr(server, "_server_config", server.ServerConfig(restrict_paths=[root]))

    # Inside an allowed root: passes.
    inside = root / "ok.bin"
    inside.touch()
    server._assert_within_restrict_roots(inside)

    # Outside every root: rejected.
    with pytest.raises(ValueError):
        server._assert_within_restrict_roots(outside)


def test_available_tools_always_returns_8_consolidated() -> None:
    """After consolidation, _available_tools always returns the same 8 tools."""
    caps = server.BinaryCapabilities(
        name="sample",
        is_elf=True,
        is_macho=True,
        has_swift=True,
        has_objc=True,
        has_hermes=True,
    )

    tools = server._available_tools(caps)
    # Format/language-specific features are now accessed via parameters
    # (info(detail="format"), functions(type="swift"), etc.)
    expected = {"load", "delete", "binaries", "info", "functions", "code", "xrefs", "search"}
    assert set(tools) == expected


def test_load_tool_schema_exposes_bootstrap_mode_enum() -> None:
    """load tool should publish bootstrap_mode as an enum in its MCP schema."""
    tool = server.mcp._tool_manager._tools["load"]
    schema = tool.parameters
    bootstrap_mode = schema["properties"]["bootstrap_mode"]

    assert bootstrap_mode["type"] == "string"
    assert bootstrap_mode["default"] == "named"
    assert bootstrap_mode["enum"] == ["named", "all"]


def test_tool_schemas_publish_enum_and_bounds() -> None:
    """MCP tool schemas should expose constrained enums and numeric/list bounds."""
    info_schema = server.mcp._tool_manager._tools["info"].parameters
    functions_schema = server.mcp._tool_manager._tools["functions"].parameters
    code_schema = server.mcp._tool_manager._tools["code"].parameters
    xrefs_schema = server.mcp._tool_manager._tools["xrefs"].parameters
    search_schema = server.mcp._tool_manager._tools["search"].parameters

    assert info_schema["properties"]["detail"]["enum"] == [
        "summary", "full", "format", "sections", "entropy"
    ]
    assert functions_schema["properties"]["type"]["enum"] == [
        "all", "swift", "objc", "imports", "exports", "types", "got", "dylibs"
    ]
    assert code_schema["properties"]["what"]["enum"] == ["decompile", "asm", "bytes", "string"]
    assert xrefs_schema["properties"]["direction"]["enum"] == ["to", "from"]
    assert xrefs_schema["properties"]["depth"]["maximum"] == 5
    assert xrefs_schema["properties"]["target"]["anyOf"][1]["maxItems"] == 20
    assert search_schema["required"] == ["binary", "query"]
    assert search_schema["properties"]["type"]["enum"] == [
        "strings", "symbols", "bytes", "all", "blob", "extract"
    ]
    assert search_schema["properties"]["mode"]["enum"] == ["indexed", "deep"]


def test_all_tools_declare_annotations() -> None:
    """Every consolidated tool must publish MCP behavioral annotations."""
    tools = server.mcp._tool_manager._tools
    expected = {"load", "delete", "binaries", "info", "functions", "code", "xrefs", "search",
                "annotate"}
    assert set(tools) == expected
    for name, tool in tools.items():
        assert tool.annotations is not None, f"{name} is missing annotations"
        assert tool.annotations.title, f"{name} is missing a title"


def test_read_only_tools_marked_read_only_and_idempotent() -> None:
    """Analysis tools must advertise readOnlyHint + idempotentHint, not destructive."""
    tools = server.mcp._tool_manager._tools
    for name in ("binaries", "info", "functions", "code", "xrefs", "search"):
        ann = tools[name].annotations
        assert ann.readOnlyHint is True, f"{name} should be read-only"
        assert ann.idempotentHint is True, f"{name} should be idempotent"
        assert ann.destructiveHint is False, f"{name} should not be destructive"
        assert ann.openWorldHint is False, f"{name} operates on local binaries only"


def test_mutating_tools_have_correct_hints() -> None:
    """delete is destructive; load mutates but is non-destructive."""
    tools = server.mcp._tool_manager._tools
    delete_ann = tools["delete"].annotations
    assert delete_ann.readOnlyHint is False
    assert delete_ann.destructiveHint is True

    load_ann = tools["load"].annotations
    assert load_ann.readOnlyHint is False
    assert load_ann.destructiveHint is False


def test_load_validation_failure_returns_mcp_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Semantic tool failures should surface as CallToolResult(isError=True)."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELFvalidation")

    monkeypatch.setattr(server, "_server_config", server.ServerConfig())
    handler = server.mcp._mcp_server.request_handlers[types.CallToolRequest]

    req = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="load",
            arguments={"path": str(binary), "bootstrap_mode": "all"},
        ),
    )

    result = asyncio.run(handler(req)).root

    assert result.isError is True
    assert "bootstrap_mode requires bootstrap" in result.content[0].text


def test_load_deep_bootstrap_keeps_existing_fast_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requesting a deep analysis should not reuse or delete an existing fast cache."""
    from unittest.mock import MagicMock

    class DummyCtx:
        async def report_progress(self, *_args):
            return None

    binary = tmp_path / "2.1.74"
    binary.write_bytes(b"\x7fELF" + b"\0" * (11 * 1024 * 1024))

    monkeypatch.setattr(server, "_server_config", server.ServerConfig(
        project_dir=tmp_path / "projects",
    ))
    monkeypatch.setattr(server, "_backend", MagicMock())

    unit_id = server.compute_unit_id_streaming(binary)
    fast_project = server._server_config.project_dir / unit_id
    fast_project.mkdir(parents=True)
    (fast_project / ".analysis_status").write_text(
        '{"status":"complete","binary_name":"2.1.74","profile":"fast","functions":10}'
    )
    (fast_project / f"{unit_id}.gpr").touch()

    created = []

    def _capture_task(coro):
        created.append(coro)
        coro.close()
        return MagicMock()

    monkeypatch.setattr(asyncio, "create_task", _capture_task)
    monkeypatch.setattr(server, "_normalize_bootstrap_source", lambda *_args: "1e5c1011ec899ef0-deep")

    result = asyncio.run(
        server.load(
            str(binary),
            DummyCtx(),
            profile="deep",
            bootstrap="2.1.70-1e5c1011-deep",
        )
    )

    assert result["status"] == "queued"
    assert result["unit_id"] == unit_id
    assert result["analysis_id"] == f"{unit_id}-deep"
    assert result["bootstrap"]["source_analysis_id"] == "1e5c1011ec899ef0-deep"
    assert fast_project.exists(), "existing fast project should remain untouched"
    assert len(created) == 1, "deep analysis should queue a new worker instead of reusing fast cache"


# =============================================================================
# Tests added for 0.4.0 features
# =============================================================================

def test_available_tools_returns_8_consolidated() -> None:
    """_available_tools returns the 8 consolidated tools (always the same)."""
    caps = server.BinaryCapabilities(name="sample")
    tools = server._available_tools(caps)
    expected = {"load", "delete", "binaries", "info", "functions", "code", "xrefs", "search"}
    assert set(tools) == expected


def test_available_tools_ignores_capabilities() -> None:
    """All 8 tools are available regardless of capabilities (auto-detection)."""
    caps_minimal = server.BinaryCapabilities(name="sample")
    caps_full = server.BinaryCapabilities(
        name="sample", is_elf=True, has_swift=True, has_objc=True
    )
    assert server._available_tools(caps_minimal) == server._available_tools(caps_full)


def test_format_capabilities_stays_lowercase() -> None:
    """Regression: PR #4 flipped to title case. Must stay lowercase for client compat."""
    caps = server.BinaryCapabilities(
        name="sample",
        is_elf=True, is_macho=True, is_pe=True,
        has_swift=True, has_objc=True, has_hermes=True,
    )
    result = server._format_capabilities(caps)
    assert "elf" in result, "capabilities must use lowercase 'elf'"
    assert "macho" in result, "capabilities must use lowercase 'macho'"
    assert "pe" in result
    assert "swift" in result
    assert "objc" in result
    assert "hermes" in result
    # Explicitly not title-case
    assert "ELF" not in result
    assert "Mach-O" not in result


def _make_ghidra_tools_stub():
    """Create a GhidraTools instance with mocked Ghidra program (no JVM needed).

    The mock program has an empty memory with no blocks, which is enough to
    exercise find_bytes() validation before any actual search occurs.
    """
    from unittest.mock import MagicMock
    from pyghidra_lite.tools import GhidraTools

    handle = MagicMock()
    handle.unit_id = "a" * 16
    gt = GhidraTools.__new__(GhidraTools)
    gt.handle = handle
    gt.program = handle.program
    gt.decompiler = handle.decompiler
    # Empty memory -- validation runs before iteration
    gt.program.getMemory().getBlocks.return_value = []
    return gt


def test_find_bytes_validation_empty_pattern() -> None:
    """find_bytes must reject empty patterns before any JVM call."""
    gt = _make_ghidra_tools_stub()
    with pytest.raises(ValueError, match="empty"):
        gt.find_bytes("")


def test_find_bytes_validation_too_long() -> None:
    """find_bytes must reject patterns longer than 128 bytes (256 hex chars)."""
    gt = _make_ghidra_tools_stub()
    with pytest.raises(ValueError, match="too long"):
        gt.find_bytes("aa" * 129)  # 129 bytes = 258 hex chars


def test_find_bytes_validation_odd_length() -> None:
    """find_bytes must reject patterns with an odd number of hex digits."""
    gt = _make_ghidra_tools_stub()
    with pytest.raises(ValueError, match="even"):
        gt.find_bytes("abc")


def test_find_bytes_validation_invalid_hex() -> None:
    """find_bytes must reject strings that are not valid hex."""
    gt = _make_ghidra_tools_stub()
    with pytest.raises(ValueError, match="Invalid hex"):
        gt.find_bytes("zzzz")


def test_find_bytes_handles_uppercase_0X_prefix() -> None:
    """Regression: 0XDEADBEEF should be handled the same as 0xdeadbeef."""
    gt = _make_ghidra_tools_stub()
    # Should NOT raise -- validation passes, returns empty list (no memory blocks)
    result = gt.find_bytes("0XDEADBEEF")
    assert result == []


def test_consolidated_tools_cover_v0_5_features() -> None:
    """v0.5.0 layer-aware features are now in 'search' and 'info' consolidated tools."""
    tools = server.mcp._tool_manager._tools
    # search handles: detect_embedded_runtime (via info), search_strings_deep, batch_search_strings
    assert "search" in tools
    assert "info" in tools


def test_no_deprecated_get_event_loop() -> None:
    """Regression: asyncio.get_event_loop() was replaced with get_running_loop()."""
    import inspect
    fns = [
        server.server_lifespan,
        server._run_worker,
        server._hot_load,
        server.load,  # Consolidated tool replacing import_binary
    ]
    for fn in fns:
        src = inspect.getsource(fn)
        assert "get_event_loop()" not in src, (
            f"{fn.__name__} still uses deprecated asyncio.get_event_loop()"
        )


def test_file_consolidation_formats_importable() -> None:
    from pyghidra_lite.formats import ElfTools, MachOTools
    assert ElfTools is not None
    assert MachOTools is not None


def test_file_consolidation_lang_importable() -> None:
    from pyghidra_lite.lang import SwiftTools, ObjCTools, demangle_swift
    assert SwiftTools is not None
    assert ObjCTools is not None
    assert demangle_swift is not None


def test_total_tool_count_is_9() -> None:
    """Tool consolidation: 58 tools -> 8 read tools + 1 opt-in write tool (annotate)."""
    import re
    src = open("src/pyghidra_lite/server.py").read()
    # Decorators now carry MCP tool annotations, e.g. @mcp.tool(annotations=...),
    # so match the opening @mcp.tool( rather than the bare ().
    count = len(re.findall(r"^@mcp\.tool\(", src, re.MULTILINE))
    assert count == 9, f"Expected exactly 9 @mcp.tool() decorators, found {count}"


# =============================================================================
# Tests added for 0.5.1 bootstrap / version-tracking fixes (PR #8 follow-up)
# =============================================================================

def _make_mock_handle(
    name: str,
    unit_id: str,
    named: int,
    total: int,
    analyzed: bool = True,
    synthetic: int = 0,
):
    """Build a minimal mock ProgramHandle for bootstrap tests (no JVM)."""
    from unittest.mock import MagicMock

    handle = MagicMock()
    handle.name = name
    handle.unit_id = unit_id
    handle.analyzed = analyzed

    fm = MagicMock()
    fm.getFunctionCount.return_value = total

    def _fake_functions(forward=True):
        funcs = []
        # named_functions get human names; rest get FUN_* auto-names
        for i in range(named):
            f = MagicMock()
            f.getName.return_value = f"real_func_{i}"
            funcs.append(f)
        for i in range(synthetic):
            f = MagicMock()
            f.getName.return_value = f"{server._BOOTSTRAP_AUTO_PREFIX}_{i:08X}"
            funcs.append(f)
        for i in range(total - named - synthetic):
            f = MagicMock()
            f.getName.return_value = f"FUN_{i:08x}"
            funcs.append(f)
        return iter(funcs)

    fm.getFunctions.side_effect = _fake_functions
    handle.program.getFunctionManager.return_value = fm
    return handle


def test_rank_bootstrap_sources_sorted_descending(monkeypatch: pytest.MonkeyPatch) -> None:
    """rank_bootstrap_sources sorts by transferable_functions descending."""
    from unittest.mock import MagicMock

    handle_a = _make_mock_handle("claude-old", "a" * 16, named=800, total=1000)
    handle_b = _make_mock_handle("claude-new", "b" * 16, named=200, total=1000)

    backend = MagicMock()
    backend.programs = {"a" * 16: handle_a, "b" * 16: handle_b}

    monkeypatch.setattr(server, "_backend", backend)
    monkeypatch.setattr(server, "get_backend", lambda: backend)

    result = server._rank_sources_blocking()

    assert len(result) == 2
    assert result[0]["name"] == "claude-old"
    assert result[0]["transferable_functions"] == 800
    assert result[0]["named_functions"] == 800
    assert result[1]["name"] == "claude-new"
    assert result[1]["transferable_functions"] == 200
    assert result[1]["named_functions"] == 200
    # Descending order
    assert result[0]["transferable_functions"] >= result[1]["transferable_functions"]


def test_rank_bootstrap_sources_excludes_dest(monkeypatch: pytest.MonkeyPatch) -> None:
    """_rank_sources_blocking excludes the dest_binary from results."""
    from unittest.mock import MagicMock

    handle_a = _make_mock_handle("source", "a" * 16, named=500, total=1000)
    handle_b = _make_mock_handle("dest", "b" * 16, named=100, total=1000)

    backend = MagicMock()
    backend.programs = {"a" * 16: handle_a, "b" * 16: handle_b}

    monkeypatch.setattr(server, "_backend", backend)
    monkeypatch.setattr(server, "get_backend", lambda: backend)

    result = server._rank_sources_blocking(exclude_name="dest")
    names = [r["name"] for r in result]
    assert "dest" not in names
    assert "source" in names


def test_rank_bootstrap_sources_named_pct(monkeypatch: pytest.MonkeyPatch) -> None:
    """named_pct field is rounded percentage of named/total."""
    from unittest.mock import MagicMock

    handle = _make_mock_handle("binary", "a" * 16, named=1, total=4)
    backend = MagicMock()
    backend.programs = {"a" * 16: handle}
    monkeypatch.setattr(server, "_backend", backend)
    monkeypatch.setattr(server, "get_backend", lambda: backend)

    result = server._rank_sources_blocking()
    assert result[0]["named_pct"] == 25.0
    assert result[0]["transferable_pct"] == 25.0


def test_rank_bootstrap_sources_counts_synthetic_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic bootstrap labels improve transferability without inflating named_functions."""
    from unittest.mock import MagicMock

    handle = _make_mock_handle("binary", "a" * 16, named=2, synthetic=3, total=10)
    backend = MagicMock()
    backend.programs = {"a" * 16: handle}
    monkeypatch.setattr(server, "_backend", backend)
    monkeypatch.setattr(server, "get_backend", lambda: backend)

    result = server._rank_sources_blocking()

    assert result[0]["named_functions"] == 2
    assert result[0]["synthetic_bootstrap_functions"] == 3
    assert result[0]["transferable_functions"] == 5
    assert result[0]["named_pct"] == 20.0
    assert result[0]["transferable_pct"] == 50.0


def test_apply_bootstrap_transfer_calls_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """_apply_bootstrap_transfer should call backend.transfer_analysis with resolved handles."""
    from unittest.mock import MagicMock

    source = MagicMock()
    source.name = "source-prog"
    source.unit_id = "a" * 16
    source.analyzed = True

    dest = MagicMock()
    dest.name = "dest-prog"
    dest.unit_id = "b" * 16
    dest.analyzed = True

    backend = MagicMock()
    backend.transfer_analysis.return_value = {"transferred": 7}

    monkeypatch.setattr(server, "_resolve_bootstrap_handle", lambda _backend, _bootstrap: source)

    result = server._apply_bootstrap_transfer(backend, "source", dest)

    assert result["transferred"] == 7
    assert result["mode"] == "named"
    backend.transfer_analysis.assert_called_once_with(
        "source-prog",
        "dest-prog",
        label_fun_star=False,
        fun_star_prefix=server._BOOTSTRAP_AUTO_PREFIX,
    )


def test_apply_bootstrap_transfer_all_mode_labels_fun_star(monkeypatch: pytest.MonkeyPatch) -> None:
    """all mode should request synthetic labels for FUN_* source functions."""
    from unittest.mock import MagicMock

    source = MagicMock()
    source.name = "source-prog"
    source.unit_id = "a" * 16
    source.analyzed = True

    dest = MagicMock()
    dest.name = "dest-prog"
    dest.unit_id = "b" * 16
    dest.analyzed = True

    backend = MagicMock()
    backend.transfer_analysis.return_value = {"transferred": 7}

    monkeypatch.setattr(server, "_resolve_bootstrap_handle", lambda _backend, _bootstrap: source)

    result = server._apply_bootstrap_transfer(backend, "source", dest, mode="all")

    assert result["mode"] == "all"
    assert result["synthetic_prefix"] == server._BOOTSTRAP_AUTO_PREFIX
    backend.transfer_analysis.assert_called_once_with(
        "source-prog",
        "dest-prog",
        label_fun_star=True,
        fun_star_prefix=server._BOOTSTRAP_AUTO_PREFIX,
    )


def test_apply_bootstrap_transfer_rejects_same_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bootstrap source and destination must be different binaries."""
    from unittest.mock import MagicMock

    source = MagicMock()
    source.name = "same-prog"
    source.unit_id = "a" * 16
    source.analyzed = True

    dest = MagicMock()
    dest.name = "same-prog"
    dest.unit_id = "a" * 16
    dest.analyzed = True

    backend = MagicMock()

    monkeypatch.setattr(server, "_resolve_bootstrap_handle", lambda _backend, _bootstrap: source)

    with pytest.raises(ValueError, match="bootstrap source must differ"):
        server._apply_bootstrap_transfer(backend, "source", dest)


def test_load_forwards_bootstrap_to_import_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load() should pass the canonical bootstrap source and mode into the blocking import path."""
    from unittest.mock import MagicMock

    class DummyCtx:
        async def report_progress(self, *_args):
            return None

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELFbootstrap")

    handle = MagicMock()
    handle.name = "sample.bin-12345678"
    handle.unit_id = "b" * 16
    handle.was_preexisting = False

    caps = server.BinaryCapabilities(name=handle.name, is_elf=True)
    captured: dict[str, str | None] = {}

    def fake_do_import_blocking(
        p,
        profile_enum,
        analyze,
        tracker,
        fresh=False,
        bootstrap=None,
        bootstrap_mode="named",
    ):
        captured["bootstrap"] = bootstrap
        captured["bootstrap_mode"] = bootstrap_mode
        return handle, caps, {"transferred": 5, "mode": bootstrap_mode}

    monkeypatch.setattr(server, "_server_config", server.ServerConfig())
    monkeypatch.setattr(server, "_backend", MagicMock())
    monkeypatch.setattr(server, "_normalize_bootstrap_source", lambda _bootstrap, _dest: "a" * 16)
    monkeypatch.setattr(server, "_do_import_blocking", fake_do_import_blocking)

    result = asyncio.run(
        server.load(
            str(binary),
            DummyCtx(),
            bootstrap="source-bin",
            bootstrap_mode="all",
        )
    )

    assert captured["bootstrap"] == "a" * 16
    assert captured["bootstrap_mode"] == "all"
    assert result["bootstrap"]["source_unit_id"] == "a" * 16
    assert result["bootstrap"]["stats"]["transferred"] == 5
    assert result["bootstrap"]["mode"] == "all"
    assert result["binary_name"] == "sample.bin"


def test_load_rejects_bootstrap_mode_without_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load() should reject non-default bootstrap_mode when bootstrap is absent."""

    class DummyCtx:
        async def report_progress(self, *_args):
            return None

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELForphaned-mode")

    monkeypatch.setattr(server, "_server_config", server.ServerConfig())

    with pytest.raises(ValueError, match="bootstrap_mode requires bootstrap"):
        asyncio.run(server.load(str(binary), DummyCtx(), bootstrap_mode="all"))


def test_load_rejects_invalid_bootstrap_mode_even_without_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load() should validate bootstrap_mode regardless of whether bootstrap is set."""

    class DummyCtx:
        async def report_progress(self, *_args):
            return None

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELFinvalid-mode")

    monkeypatch.setattr(server, "_server_config", server.ServerConfig())

    with pytest.raises(ValueError, match="Invalid bootstrap_mode"):
        asyncio.run(server.load(str(binary), DummyCtx(), bootstrap_mode="garbage"))


def test_kill_job_acquires_jobs_mutex() -> None:
    """_kill_job removes entry from _active_jobs under _jobs_mutex; SIGTERM on live pid."""
    import signal as _signal
    from unittest.mock import patch

    server._active_jobs["test_uid"] = {"status": "analyzing", "pid": None}
    with patch.object(_signal, "SIGTERM", _signal.SIGTERM):
        server._kill_job("test_uid")

    assert "test_uid" not in server._active_jobs


def test_kill_job_sends_sigterm(monkeypatch: pytest.MonkeyPatch) -> None:
    """_kill_job sends SIGTERM to the stored pid."""
    signals_sent = []

    def _fake_kill(pid, sig):
        signals_sent.append((pid, sig))

    monkeypatch.setattr(server.os, "kill", _fake_kill)
    server._active_jobs["uid2"] = {"status": "analyzing", "pid": 99999}
    server._kill_job("uid2")

    assert "uid2" not in server._active_jobs
    assert (99999, server.signal.SIGTERM) in signals_sent


def test_delete_ambiguous_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """delete should reject ambiguous partial matches."""
    import asyncio
    from unittest.mock import MagicMock

    handle_a = MagicMock()
    handle_a.name = "claude-aaaaaaaaaaaaaaa1"
    handle_a.unit_id = "a" * 16

    handle_b = MagicMock()
    handle_b.name = "claude-bbbbbbbbbbbbbb1"
    handle_b.unit_id = "b" * 16

    backend = MagicMock()
    backend.programs = {"a" * 16: handle_a, "b" * 16: handle_b}
    monkeypatch.setattr(server, "_backend", backend)
    monkeypatch.setattr(server, "get_backend", lambda: backend)

    config = server.ServerConfig()
    monkeypatch.setattr(server, "_server_config", config)

    with pytest.raises(ValueError, match="Ambiguous"):
        # "claude" is a substring of both handle names
        asyncio.run(server.delete("claude", None))

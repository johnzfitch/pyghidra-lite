import asyncio
import os
from pathlib import Path

import pytest
from mcp.shared.exceptions import McpError
from mcp.types import INVALID_PARAMS

from pyghidra_lite import server


def test_resolve_import_path_requires_allowlist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = server.ServerConfig(allowed_paths=[], allow_any_path=False)
    monkeypatch.setattr(server, "_server_config", config)
    target = tmp_path / "sample.bin"

    with pytest.raises(ValueError):
        server._resolve_import_path(str(target))


def test_resolve_import_path_allows_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "sample.bin"
    config = server.ServerConfig(allowed_paths=[root])
    monkeypatch.setattr(server, "_server_config", config)

    resolved = server._resolve_import_path(str(target))
    assert resolved == target.resolve()


def test_resolve_import_path_blocks_outside_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "other.bin"
    config = server.ServerConfig(allowed_paths=[root])
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
    config = server.ServerConfig(allowed_paths=[root])
    monkeypatch.setattr(server, "_server_config", config)

    with pytest.raises(ValueError) as exc:
        server._resolve_import_path(str(link))

    msg = str(exc.value)
    assert "requested=" in msg
    assert "resolves_to=" in msg
    assert str(link.resolve()) in msg
    assert "--allow-path" in msg


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


def test_guarded_tool_call_maps_invalid_params() -> None:
    def op():
        raise ValueError("bad")

    with pytest.raises(McpError) as exc:
        server._guarded_tool_call("test", op)

    error = getattr(exc.value, "error", None) or getattr(exc.value, "data", None)
    assert error is not None
    assert error.code == INVALID_PARAMS


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
    # Empty memory — validation runs before iteration
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
    # Should NOT raise — validation passes, returns empty list (no memory blocks)
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


def test_total_tool_count_is_8() -> None:
    """Tool consolidation: 58 tools -> 8 consolidated tools."""
    import re
    src = open("src/pyghidra_lite/server.py").read()
    count = len(re.findall(r"^@mcp\.tool\(\)", src, re.MULTILINE))
    assert count == 8, f"Expected exactly 8 @mcp.tool() decorators, found {count}"


# =============================================================================
# Tests added for 0.5.1 bootstrap / version-tracking fixes (PR #8 follow-up)
# =============================================================================

def _make_mock_handle(name: str, unit_id: str, named: int, total: int, analyzed: bool = True):
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
        for i in range(total - named):
            f = MagicMock()
            f.getName.return_value = f"FUN_{i:08x}"
            funcs.append(f)
        return iter(funcs)

    fm.getFunctions.side_effect = _fake_functions
    handle.program.getFunctionManager.return_value = fm
    return handle


def test_rank_bootstrap_sources_sorted_descending(monkeypatch: pytest.MonkeyPatch) -> None:
    """rank_bootstrap_sources (via _rank_sources_blocking) returns list sorted by named_functions desc."""
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
    assert result[0]["named_functions"] == 800
    assert result[1]["name"] == "claude-new"
    assert result[1]["named_functions"] == 200
    # Descending order
    assert result[0]["named_functions"] >= result[1]["named_functions"]


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
    backend.transfer_analysis.assert_called_once_with("source-prog", "dest-prog")


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

    with pytest.raises(McpError) as exc:
        server._apply_bootstrap_transfer(backend, "source", dest)

    error = getattr(exc.value, "error", None) or getattr(exc.value, "data", None)
    assert error is not None
    assert error.code == INVALID_PARAMS


def test_load_forwards_bootstrap_to_import_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load() should pass the canonical bootstrap source into the blocking import path."""
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
    ):
        captured["bootstrap"] = bootstrap
        return handle, caps, {"transferred": 5}

    monkeypatch.setattr(server, "_server_config", server.ServerConfig(allow_any_path=True))
    monkeypatch.setattr(server, "_backend", MagicMock())
    monkeypatch.setattr(server, "_normalize_bootstrap_source", lambda _bootstrap, _dest: "a" * 16)
    monkeypatch.setattr(server, "_do_import_blocking", fake_do_import_blocking)

    result = asyncio.run(server.load(str(binary), DummyCtx(), bootstrap="source-bin"))

    assert captured["bootstrap"] == "a" * 16
    assert result["bootstrap"]["transferred"] == 5
    assert result["binary_name"] == "sample.bin"


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
    """delete raises INVALID_PARAMS when multiple handles share the substring."""
    import asyncio
    from unittest.mock import MagicMock
    from mcp.types import INVALID_PARAMS

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

    config = server.ServerConfig(allow_any_path=True)
    monkeypatch.setattr(server, "_server_config", config)

    with pytest.raises(McpError) as exc:
        # "claude" is a substring of both handle names
        asyncio.run(server.delete("claude", None))

    error = getattr(exc.value, "error", None) or getattr(exc.value, "data", None)
    assert error is not None
    assert error.code == INVALID_PARAMS
    assert "Ambiguous" in error.message

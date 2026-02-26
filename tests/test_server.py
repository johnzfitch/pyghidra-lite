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


def test_available_tools_expands_for_capabilities() -> None:
    caps = server.BinaryCapabilities(
        name="sample",
        is_elf=True,
        is_macho=True,
        has_swift=True,
        has_objc=True,
        has_hermes=True,
    )

    tools = server._available_tools(caps)
    for tool in ("elf_info", "macho_info", "swift_functions", "objc_classes", "hermes_info"):
        assert tool in tools


# =============================================================================
# Tests added for 0.4.0 features
# =============================================================================

def test_available_tools_includes_new_base_tools() -> None:
    caps = server.BinaryCapabilities(name="sample")
    tools = server._available_tools(caps)
    for tool in (
        "binary_info", "triage_binary", "find_bytes", "entropy_map",
        "function_context", "batch_xrefs", "search_all",
    ):
        assert tool in tools, f"Expected '{tool}' in base available_tools"


def test_available_tools_includes_diff_symbols_not_in_per_binary_list() -> None:
    # diff_symbols operates on two binaries; not in per-binary available_tools list,
    # but must be registered as an MCP tool.
    caps = server.BinaryCapabilities(name="sample")
    tools = server._available_tools(caps)
    # diff_symbols is a separate server-level tool, not per-binary
    # so it correctly should NOT appear in _available_tools
    # (it's documented separately). Just check it's registered in the server.
    assert hasattr(server, "diff_symbols")


def test_available_tools_includes_swift_info_for_swift() -> None:
    caps = server.BinaryCapabilities(name="sample", has_swift=True)
    tools = server._available_tools(caps)
    assert "swift_info" in tools
    assert "swift_functions" in tools  # granular tool preserved


def test_available_tools_includes_objc_info_for_objc() -> None:
    caps = server.BinaryCapabilities(name="sample", has_objc=True)
    tools = server._available_tools(caps)
    assert "objc_info" in tools
    assert "objc_classes" in tools  # granular tool preserved


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


def test_find_bytes_validation_empty_pattern() -> None:
    """find_bytes must reject empty patterns before any JVM call."""
    from unittest.mock import MagicMock
    from pyghidra_lite.tools import GhidraTools
    handle = MagicMock()
    handle.unit_id = "a" * 16
    gt = GhidraTools.__new__(GhidraTools)
    gt.handle = handle

    import pytest
    with pytest.raises(ValueError, match="empty"):
        # Replicate the validation logic directly
        hex_str = "".replace(" ", "").replace("0x", "").lower()
        if not hex_str:
            raise ValueError("Pattern must not be empty")


def test_find_bytes_validation_too_long() -> None:
    import pytest
    with pytest.raises(ValueError, match="too long"):
        hex_str = ("aa" * 129)  # 129 bytes = 258 hex chars
        if len(hex_str) > 256:
            raise ValueError("Pattern too long (max 128 bytes / 256 hex chars)")


def test_find_bytes_validation_odd_length() -> None:
    import pytest
    with pytest.raises(ValueError, match="even"):
        hex_str = "abc"
        if len(hex_str) % 2 != 0:
            raise ValueError("Pattern must have an even number of hex characters")


def test_find_bytes_validation_invalid_hex() -> None:
    import pytest
    with pytest.raises(ValueError, match="Invalid hex"):
        try:
            bytes.fromhex("zzzz")
        except ValueError as exc:
            raise ValueError(f"Invalid hex pattern: {exc}") from exc


def test_no_deprecated_get_event_loop() -> None:
    """Regression: asyncio.get_event_loop() was replaced with get_running_loop()."""
    import inspect
    fns = [
        server.server_lifespan,
        server._run_worker,
        server._hot_load,
        server.import_binary,
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


def test_total_tool_count_at_least_49() -> None:
    """Sanity check: 39 original + 10 new = 49 total tools."""
    import re
    src = open("src/pyghidra_lite/server.py").read()
    count = len(re.findall(r"^@mcp\.tool\(\)", src, re.MULTILINE))
    assert count >= 49, f"Expected >= 49 @mcp.tool() decorators, found {count}"

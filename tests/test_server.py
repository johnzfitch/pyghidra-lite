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

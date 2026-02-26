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
    for tool in ("elf_info", "macho_info", "swift_info", "objc_info", "hermes_info"):
        assert tool in tools

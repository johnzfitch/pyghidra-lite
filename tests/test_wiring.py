"""Wiring / capability tripwire.

Asserts that the tool surface the server *advertises* maps to real, non-trivial
implementations -- so a tool can't be registered as a hollow stub and the
capability matrix (formats/languages) can't drift away from its backing code.
Complements test_red_team.py's settings-mutation tripwire.
"""
import inspect

from pyghidra_lite import server

# 8 read/analysis tools + the opt-in annotate write tool.
EXPECTED_TOOLS = {
    "load", "delete", "binaries", "info", "functions", "code", "xrefs", "search",
    "annotate",
}


def test_exact_tool_count_is_nine():
    tools = server.mcp._tool_manager.list_tools()
    assert len(tools) == 9
    assert {t.name for t in tools} == EXPECTED_TOOLS


def test_every_tool_nontrivially_wired():
    for tool in server.mcp._tool_manager.list_tools():
        src = inspect.getsource(tool.fn)
        assert len(src.splitlines()) > 5, f"{tool.name} looks like a stub"
        assert "raise NotImplementedError" not in src, f"{tool.name} is not implemented"


def test_capability_matrix_maps_to_real_impls():
    """Each functions(type=...)/info(detail=...) view has a backing implementation."""
    from pyghidra_lite import formats
    from pyghidra_lite.tools import GhidraTools

    # Cross-format function views.
    assert hasattr(GhidraTools, "list_functions")
    assert hasattr(GhidraTools, "list_imports")
    assert hasattr(GhidraTools, "list_exports")

    # Format-specific views advertised by the tools.
    assert hasattr(formats.ElfTools, "get_got_plt")
    assert hasattr(formats.ElfTools, "get_elf_info")
    assert hasattr(formats.MachOTools, "list_dylibs")
    assert hasattr(formats.MachOTools, "get_macho_info")

    # PE imports/IAT capability (new in 0.8.0).
    assert hasattr(formats, "PeTools")
    assert hasattr(formats.PeTools, "get_pe_info")
    assert hasattr(formats.PeTools, "list_imports_by_dll")


def test_write_capability_only_via_annotate():
    """annotate is the single write tool; the analysis tools stay read-only."""
    from pyghidra_lite.backend import GhidraBackend

    # The persistence helper that annotate relies on must exist.
    assert hasattr(GhidraBackend, "save_program")

    tools = server.mcp._tool_manager._tools
    assert tools["annotate"].annotations.readOnlyHint is False

    for name in ("info", "functions", "code", "xrefs", "search", "binaries"):
        assert tools[name].annotations.readOnlyHint is True, f"{name} must stay read-only"

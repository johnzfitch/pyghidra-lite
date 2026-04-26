"""Tests for detect_embedded_runtime."""

from unittest.mock import MagicMock

import pytest

from pyghidra_lite.tools import GhidraTools


def _make_stub() -> GhidraTools:
    handle = MagicMock()
    handle.unit_id = "b" * 16
    gt = GhidraTools.__new__(GhidraTools)
    gt.handle = handle
    gt.program = handle.program
    gt.decompiler = handle.decompiler
    gt.program.getMemory().getBlocks.return_value = []
    return gt


def _stub_find_bytes(magic_map: dict):
    """Return a find_bytes side_effect that maps pattern -> hit list."""
    def side_effect(pattern, limit=20):
        return magic_map.get(pattern, [])
    return side_effect


# =============================================================================
# Basic detection
# =============================================================================

class TestDetectEmbeddedRuntimeBasic:
    def test_no_signatures_returns_not_detected(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(return_value=[])
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        assert result["detected"] is False
        assert result["runtimes"] == []

    def test_bunfs_detected_compact(self):
        """BUN\\x00 magic -> bunfs, high confidence, external_tools."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "42554e00": [{"address": "0x1000000", "section": ".data"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime(compact=True)
        assert result["detected"] is True
        rt = next(r for r in result["runtimes"] if r["type"] == "bunfs")
        assert rt["confidence"] == "high"
        assert rt["strategy"] == "external_tools"
        # Compact: no payload_offset for external_tools
        assert "payload_offset" not in rt

    def test_upx_detected(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "55505821": [{"address": "0x0", "section": "Headers"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        rt = next((r for r in result["runtimes"] if r["type"] == "upx"), None)
        assert rt is not None
        assert rt["strategy"] == "unpack_first"
        assert rt["confidence"] == "high"

    def test_pyinstaller_detected(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "4d45490e34120100": [{"address": "0x200000", "section": ".data"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        rt = next((r for r in result["runtimes"] if r["type"] == "pyinstaller"), None)
        assert rt is not None
        assert rt["strategy"] == "external_tools"

    def test_lua_bytecode_detected(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "1b4c7561": [{"address": "0x300000", "section": ".rodata"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        rt = next((r for r in result["runtimes"] if r["type"] == "lua_bytecode"), None)
        assert rt is not None
        assert rt["confidence"] == "high"


# =============================================================================
# ASAR confidence adjustments
# =============================================================================

class TestAsarConfidence:
    def test_asar_in_rodata_high_confidence_with_payload_offset(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "41534152": [{"address": "0x2000000", "section": ".rodata"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime(compact=True)
        asar = next((r for r in result["runtimes"] if r["type"] == "electron_asar"), None)
        assert asar is not None
        assert asar["confidence"] == "high"
        assert asar["strategy"] == "search_payload"
        assert asar["payload_offset"] == "0x2000000"

    def test_asar_in_data_high_confidence(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "41534152": [{"address": "0x2000000", "section": ".data"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        asar = next((r for r in result["runtimes"] if r["type"] == "electron_asar"), None)
        assert asar is not None
        assert asar["confidence"] == "high"

    def test_asar_in_text_omitted(self):
        """ASAR magic in .text -> likely false positive, omitted."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "41534152": [{"address": "0x500000", "section": ".text"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        types = [r["type"] for r in result["runtimes"]]
        assert "electron_asar" not in types


# =============================================================================
# Node SEA confidence adjustments
# =============================================================================

class TestNodeSeaConfidence:
    _NODE_SEA_MAGIC = "4e4f44455f5345415f46555345"

    def test_node_sea_in_data_detected(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            self._NODE_SEA_MAGIC: [{"address": "0x100000", "section": ".data"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        sea = next((r for r in result["runtimes"] if r["type"] == "node_sea"), None)
        assert sea is not None
        assert sea["strategy"] == "search_payload"

    def test_node_sea_in_strtab_omitted(self):
        """NODE_SEA_FUSE in .strtab -> likely just the symbol name, omitted."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            self._NODE_SEA_MAGIC: [{"address": "0x100000", "section": ".strtab"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        types = [r["type"] for r in result["runtimes"]]
        assert "node_sea" not in types


# =============================================================================
# V8 snapshot confidence (symbol vs magic)
# =============================================================================

class TestV8SnapshotConfidence:
    def test_v8_via_symbol_high_confidence(self):
        """v8_snapshot_blob_data symbol found -> confidence upgraded to high."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(return_value=[])

        sym = MagicMock()
        sym.getName.return_value = "v8_snapshot_blob_data"
        sym_addr = MagicMock()
        sym_addr.__str__ = lambda self: "0x3000000"
        sym.getAddress.return_value = sym_addr
        gt.program.getSymbolTable().getAllSymbols.return_value = [sym]

        block = MagicMock()
        block.getName.return_value = ".rodata"
        gt.program.getMemory().getBlock.return_value = block

        result = gt.detect_embedded_runtime(compact=True)
        v8 = next((r for r in result["runtimes"] if r["type"] == "v8_snapshot"), None)
        assert v8 is not None
        assert v8["confidence"] == "high"
        # find_bytes should NOT have been called with the v8 magic bytes;
        # symbol lookup succeeded, so the magic-byte fallback was skipped.
        v8_magic = "d80dcace"
        called_patterns = [call[0][0] for call in gt.find_bytes.call_args_list]
        assert v8_magic not in called_patterns, (
            f"find_bytes({v8_magic!r}) should not be called when symbol found first"
        )

    def test_v8_magic_only_medium_confidence(self):
        """Magic bytes only (no symbol) -> stays at medium confidence."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "d80dcace": [{"address": "0x4000000", "section": ".data"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime()
        v8 = next((r for r in result["runtimes"] if r["type"] == "v8_snapshot"), None)
        assert v8 is not None
        assert v8["confidence"] == "medium"


# =============================================================================
# Compact vs verbose output
# =============================================================================

class TestCompactVerboseOutput:
    def test_compact_excludes_magic_address_and_section(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "55505821": [{"address": "0x0", "section": "Headers"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime(compact=True)
        upx = next(r for r in result["runtimes"] if r["type"] == "upx")
        assert "magic_address" not in upx
        assert "section" not in upx

    def test_verbose_includes_magic_address_and_section(self):
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "55505821": [{"address": "0x0", "section": "Headers"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime(compact=False)
        upx = next(r for r in result["runtimes"] if r["type"] == "upx")
        assert "magic_address" in upx
        assert upx["magic_address"] == "0x0"
        assert "section" in upx
        assert upx["section"] == "Headers"

    def test_search_payload_includes_payload_offset_in_compact(self):
        """payload_offset appears in compact mode when strategy == search_payload."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "41534152": [{"address": "0xABC000", "section": ".rodata"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime(compact=True)
        asar = next(r for r in result["runtimes"] if r["type"] == "electron_asar")
        assert "payload_offset" in asar
        assert asar["payload_offset"] == "0xABC000"

    def test_external_tools_no_payload_offset(self):
        """payload_offset absent for external_tools strategy (e.g., bunfs)."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "42554e00": [{"address": "0x1000000", "section": ".data"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime(compact=True)
        bunfs = next(r for r in result["runtimes"] if r["type"] == "bunfs")
        assert "payload_offset" not in bunfs

    def test_multiple_runtimes_detected(self):
        """Multiple signatures can be detected in one call."""
        gt = _make_stub()
        gt.find_bytes = MagicMock(side_effect=_stub_find_bytes({
            "42554e00": [{"address": "0x1000", "section": ".data"}],
            "55505821": [{"address": "0x2000", "section": "Headers"}],
        }))
        gt.program.getSymbolTable().getAllSymbols.return_value = []

        result = gt.detect_embedded_runtime(compact=True)
        assert result["detected"] is True
        types = {r["type"] for r in result["runtimes"]}
        assert "bunfs" in types
        assert "upx" in types

"""Tests for search_strings_deep, batch_search_strings, and extract_strings_from_blob."""

from unittest.mock import MagicMock

import pytest

from pyghidra_lite.tools import GhidraTools


def _make_stub() -> GhidraTools:
    """GhidraTools stub with empty mocked program (no JVM needed)."""
    handle = MagicMock()
    handle.unit_id = "a" * 16
    gt = GhidraTools.__new__(GhidraTools)
    gt.handle = handle
    gt.program = handle.program
    gt.decompiler = handle.decompiler
    gt.program.getMemory().getBlocks.return_value = []
    return gt


# =============================================================================
# search_strings_deep
# =============================================================================

class TestSearchStringsDeep:
    def test_empty_memory_returns_empty(self):
        gt = _make_stub()
        assert gt.search_strings_deep("test") == []

    def test_skips_uninitialized_blocks(self):
        gt = _make_stub()
        block = MagicMock()
        block.isInitialized.return_value = False
        block.getName.return_value = ".bss"
        gt.program.getMemory().getBlocks.return_value = [block]
        assert gt.search_strings_deep("test") == []
        block.getSize.assert_not_called()

    def test_section_filter_skips_non_matching(self):
        """When sections=[".rodata"], blocks with other names are skipped."""
        gt = _make_stub()
        block = MagicMock()
        block.isInitialized.return_value = True
        block.getName.return_value = ".strtab"
        block.getSize.return_value = 0
        gt.program.getMemory().getBlocks.return_value = [block]
        result = gt.search_strings_deep("test", sections=[".rodata"])
        assert result == []

    def test_section_filter_includes_matching(self):
        """When sections=[".strtab"], only the .strtab block is scanned."""
        gt = _make_stub()
        block_match = MagicMock()
        block_match.isInitialized.return_value = True
        block_match.getName.return_value = ".strtab"
        block_match.getSize.return_value = 0  # no bytes, so no results
        block_other = MagicMock()
        block_other.isInitialized.return_value = True
        block_other.getName.return_value = ".rodata"
        block_other.getSize.return_value = 0
        gt.program.getMemory().getBlocks.return_value = [block_match, block_other]
        gt.search_strings_deep("test", sections=[".strtab"])
        # block_match.getSize was accessed; block_other should not be scanned
        block_match.getSize.assert_called()

    def test_skip_high_entropy_calls_entropy_map(self):
        gt = _make_stub()
        gt.entropy_map = MagicMock(return_value=[
            {"name": ".text", "entropy": 7.9, "size": 1000, "note": "likely encrypted/packed"},
        ])
        gt.search_strings_deep("test", skip_high_entropy=True)
        gt.entropy_map.assert_called_once()

    def test_skip_high_entropy_false_does_not_call_entropy_map(self):
        gt = _make_stub()
        gt.entropy_map = MagicMock(return_value=[])
        gt.search_strings_deep("test", skip_high_entropy=False)
        gt.entropy_map.assert_not_called()

    def test_skip_high_entropy_excludes_high_entropy_sections(self):
        """Section with entropy > 7.5 is skipped when skip_high_entropy=True."""
        gt = _make_stub()
        gt.entropy_map = MagicMock(return_value=[
            {"name": ".packed", "entropy": 7.9, "size": 100, "note": ""},
        ])
        block = MagicMock()
        block.isInitialized.return_value = True
        block.getName.return_value = ".packed"
        block.getSize.return_value = 0
        gt.program.getMemory().getBlocks.return_value = [block]
        result = gt.search_strings_deep("test", skip_high_entropy=True)
        assert result == []
        # getSize should not be called on a skipped block
        block.getSize.assert_not_called()


# =============================================================================
# batch_search_strings
# =============================================================================

class TestBatchSearchStrings:
    def test_too_many_queries_raises(self):
        gt = _make_stub()
        with pytest.raises(ValueError, match="20"):
            gt.batch_search_strings(["q"] * 21)

    def test_exactly_20_queries_accepted(self):
        gt = _make_stub()
        queries = [f"query_{i}" for i in range(20)]
        result = gt.batch_search_strings(queries, compact=True)
        assert len(result) == 20

    def test_compact_returns_counts(self):
        gt = _make_stub()
        result = gt.batch_search_strings(["foo", "bar"], compact=True)
        assert result == {"foo": 0, "bar": 0}

    def test_verbose_returns_hit_lists(self):
        gt = _make_stub()
        result = gt.batch_search_strings(["foo", "bar"], compact=False)
        assert result == {"foo": [], "bar": []}

    def test_entropy_map_called_once_not_per_query(self):
        """Entropy map computed once regardless of query count."""
        gt = _make_stub()
        gt.entropy_map = MagicMock(return_value=[])
        gt.batch_search_strings(["a", "b", "c", "d"], skip_high_entropy=True)
        gt.entropy_map.assert_called_once()

    def test_entropy_map_not_called_when_not_skipping(self):
        gt = _make_stub()
        gt.entropy_map = MagicMock(return_value=[])
        gt.batch_search_strings(["a", "b"], skip_high_entropy=False)
        gt.entropy_map.assert_not_called()

    def test_all_queries_present_in_result(self):
        """Every query must appear as a key in the result, even with zero hits."""
        gt = _make_stub()
        queries = ["alpha", "beta", "gamma"]
        result = gt.batch_search_strings(queries, compact=True)
        for q in queries:
            assert q in result

    def test_indexed_mode_with_empty_defined_strings(self):
        """mode='indexed' with no defined strings returns zero for each query."""
        gt = _make_stub()
        try:
            import ghidra  # noqa: F401
        except (ImportError, ModuleNotFoundError):
            pytest.skip("Ghidra JVM not available")

        result = gt.batch_search_strings(["foo", "bar"], mode="indexed", compact=True)
        assert result == {"foo": 0, "bar": 0}


# =============================================================================
# extract_strings_from_blob
# =============================================================================

class TestExtractStringsFromBlob:
    def test_size_over_limit_raises(self):
        gt = _make_stub()
        with pytest.raises(ValueError, match="50MB"):
            gt.extract_strings_from_blob("0x1000", 51 * 1024 * 1024)

    def test_zero_size_raises(self):
        gt = _make_stub()
        with pytest.raises(ValueError):
            gt.extract_strings_from_blob("0x1000", 0)

    def test_invalid_address_raises(self):
        gt = _make_stub()
        gt.program.getAddressFactory().getAddress.side_effect = Exception("bad addr")
        gt.program.getSymbolTable().getAllSymbols.return_value = iter([])
        with pytest.raises(ValueError, match="Invalid address"):
            gt.extract_strings_from_blob("not_an_address", 100)

    def test_address_not_in_memory_raises(self):
        gt = _make_stub()
        mock_addr = MagicMock()
        mock_addr.__str__ = lambda self: "0x99999"
        gt._resolve_address = MagicMock(return_value=mock_addr)
        gt.program.getMemory().contains.return_value = False
        with pytest.raises(ValueError, match="not in memory"):
            gt.extract_strings_from_blob("0x99999", 100)

    def _run_blob_extract(self, data: bytes, **kwargs) -> list[dict]:
        """Helper: set up blob stub and call extract_strings_from_blob.

        Mocks JByte so tests run without a live JVM.
        """
        from unittest.mock import patch

        gt = _make_stub()
        mock_addr = MagicMock()
        mock_addr.__str__ = lambda self: "0x1000"
        mock_addr.add = MagicMock(return_value=mock_addr)
        gt._resolve_address = MagicMock(return_value=mock_addr)
        gt.program.getMemory().contains.return_value = True

        def fake_get_bytes(addr, buf):
            n = len(buf)
            for i, b in enumerate(data[:n]):
                buf[i] = b  # bytearray accepts 0–255
            return min(n, len(data))

        gt.program.getMemory().getBytes.side_effect = fake_get_bytes

        # Mock JByte so it returns a plain bytearray (no JVM needed).
        # Must patch jpype.JByte since it's imported locally inside the method.
        class _MockJByte:
            def __class_getitem__(cls, n):
                return bytearray(n)

        with patch("jpype.JByte", _MockJByte):
            return gt.extract_strings_from_blob("0x1000", len(data), **kwargs)

    def test_compact_output_keys(self):
        """Compact results have value+address, no blob_offset."""
        results = self._run_blob_extract(b"hello world test\x00", min_length=4, compact=True)
        assert len(results) > 0
        for r in results:
            assert "value" in r
            assert "address" in r
            assert "blob_offset" not in r

    def test_verbose_output_has_blob_offset(self):
        """Verbose results include blob_offset."""
        results = self._run_blob_extract(b"hello world test\x00", min_length=4, compact=False)
        assert len(results) > 0
        for r in results:
            assert "blob_offset" in r
            assert r["blob_offset"].startswith("0x")

    def test_query_filter_applied(self):
        """Only strings matching the query are returned."""
        data = b"matchme\x00nope_skip\x00matchmore\x00"
        results = self._run_blob_extract(data, query="match", min_length=4, compact=True)
        assert len(results) > 0
        for r in results:
            assert "match" in r["value"].lower()

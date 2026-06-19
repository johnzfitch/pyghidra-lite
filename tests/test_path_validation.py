"""Tests for path validation security boundary.

Every test here probes the EDGE of the allowlist, not specific attack strings.
The validation is allowlist-based: only 16 lowercase hex chars (unit_id) or
16 lowercase hex chars + {-fast,-default,-deep} (analysis_id) are accepted.
Tests verify acceptance at the boundary and rejection one step outside it.
"""

from pathlib import Path

import pytest

from pyghidra_lite import server
from pyghidra_lite.backend import (
    _assert_ghidra_safe_project_dir,
    _read_ghidra_major_version,
    parse_analysis_id,
)

# ---------------------------------------------------------------------------
# parse_analysis_id -- allowlist: {16 lowercase hex}-{fast|default|deep}
# ---------------------------------------------------------------------------

class TestParseAnalysisId:
    # --- accepted by the allowlist ---
    def test_valid_fast(self):
        assert parse_analysis_id("abcdef0123456789-fast") == ("abcdef0123456789", "fast")

    def test_valid_default(self):
        assert parse_analysis_id("0000000000000000-default") == ("0000000000000000", "default")

    def test_valid_deep(self):
        assert parse_analysis_id("ffffffffffffffff-deep") == ("ffffffffffffffff", "deep")

    # --- one step outside the allowlist: length ---
    def test_rejects_15_hex_chars(self):
        assert parse_analysis_id("abcdef012345678-fast") is None

    def test_rejects_17_hex_chars(self):
        assert parse_analysis_id("abcdef01234567890-fast") is None

    # --- one step outside the allowlist: character class ---
    def test_rejects_one_uppercase_char(self):
        assert parse_analysis_id("Abcdef0123456789-fast") is None

    def test_rejects_one_non_hex_char(self):
        assert parse_analysis_id("abcdef012345678g-fast") is None

    # --- one step outside the allowlist: suffix ---
    def test_rejects_unknown_suffix(self):
        assert parse_analysis_id("abcdef0123456789-turbo") is None

    def test_rejects_no_suffix(self):
        assert parse_analysis_id("abcdef0123456789") is None

    def test_rejects_empty(self):
        assert parse_analysis_id("") is None


# ---------------------------------------------------------------------------
# _validate_project_id -- allowlist: unit_id OR analysis_id
# ---------------------------------------------------------------------------

class TestValidateProjectId:
    # --- accepted: unit_id (16 hex) ---
    def test_accepts_unit_id(self):
        server._validate_project_id("abcdef0123456789")

    def test_accepts_all_zeros(self):
        server._validate_project_id("0000000000000000")

    def test_accepts_all_f(self):
        server._validate_project_id("ffffffffffffffff")

    # --- accepted: analysis_id (16 hex + suffix) ---
    def test_accepts_analysis_id_fast(self):
        server._validate_project_id("abcdef0123456789-fast")

    def test_accepts_analysis_id_default(self):
        server._validate_project_id("abcdef0123456789-default")

    def test_accepts_analysis_id_deep(self):
        server._validate_project_id("abcdef0123456789-deep")

    # --- one step outside: length ---
    def test_rejects_15_hex_chars(self):
        with pytest.raises(ValueError):
            server._validate_project_id("abcdef012345678")

    def test_rejects_17_hex_chars(self):
        with pytest.raises(ValueError):
            server._validate_project_id("abcdef01234567890")

    # --- one step outside: character class ---
    def test_rejects_one_uppercase_char(self):
        with pytest.raises(ValueError):
            server._validate_project_id("Abcdef0123456789")

    def test_rejects_one_non_hex_char(self):
        with pytest.raises(ValueError):
            server._validate_project_id("abcdef012345678g")

    # --- one step outside: suffix ---
    def test_rejects_unknown_suffix(self):
        with pytest.raises(ValueError):
            server._validate_project_id("abcdef0123456789-turbo")

    # --- edge: empty ---
    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            server._validate_project_id("")


# ---------------------------------------------------------------------------
# _safe_project_path -- format allowlist + resolve/containment
# ---------------------------------------------------------------------------

class TestSafeProjectPath:
    def test_returns_resolved_path_for_unit_id(self, tmp_path):
        result = server._safe_project_path(tmp_path, "abcdef0123456789")
        assert result == (tmp_path / "abcdef0123456789").resolve()

    def test_returns_resolved_path_for_analysis_id(self, tmp_path):
        result = server._safe_project_path(tmp_path, "abcdef0123456789-fast")
        assert result == (tmp_path / "abcdef0123456789-fast").resolve()

    def test_rejects_15_hex_chars(self, tmp_path):
        with pytest.raises(ValueError):
            server._safe_project_path(tmp_path, "abcdef012345678")

    def test_rejects_non_hex_char(self, tmp_path):
        with pytest.raises(ValueError):
            server._safe_project_path(tmp_path, "abcdef012345678g")


# ---------------------------------------------------------------------------
# _read_status_file / _write_status_file / _write_job_result
# ---------------------------------------------------------------------------

class TestPathHelperValidation:
    @pytest.fixture(autouse=True)
    def _cfg(self, tmp_path, monkeypatch):
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        self.project_dir = tmp_path

    # _read_status_file: returns {} for anything outside the allowlist
    def test_read_status_file_returns_empty_for_15_hex(self):
        assert server._read_status_file("abcdef012345678") == {}

    def test_read_status_file_returns_empty_for_empty(self):
        assert server._read_status_file("") == {}

    def test_read_status_file_accepts_valid_unit_id(self):
        assert server._read_status_file("abcdef0123456789") == {}

    # _write_status_file: rejects anything outside the allowlist
    def test_write_status_file_rejects_15_hex(self):
        with pytest.raises(ValueError):
            server._write_status_file("abcdef012345678", {"status": "complete"})

    def test_write_status_file_rejects_non_hex_char(self):
        with pytest.raises(ValueError):
            server._write_status_file("abcdef012345678g", {"status": "complete"})

    def test_write_status_file_accepts_valid(self):
        server._write_status_file("abcdef0123456789", {"status": "complete"})
        status_file = self.project_dir / "abcdef0123456789" / ".analysis_status"
        assert status_file.exists()

    # _write_job_result: tighter allowlist -- unit_id only (no analysis_id)
    def test_write_job_result_rejects_analysis_id(self):
        with pytest.raises(ValueError):
            server._write_job_result("abcdef0123456789-fast", {"result": "data"})

    def test_write_job_result_rejects_15_hex(self):
        with pytest.raises(ValueError):
            server._write_job_result("abcdef012345678", {"result": "data"})

    def test_write_job_result_accepts_valid_hex(self):
        server._write_job_result("abcdef0123456789", {"result": "data"})
        result_file = self.project_dir / "abcdef0123456789" / "result.json"
        assert result_file.exists()


# ---------------------------------------------------------------------------
# _read_ghidra_major_version -- pre-JVM parse of application.properties
# ---------------------------------------------------------------------------
class TestReadGhidraMajorVersion:
    def _make_install(self, tmp_path, version_line):
        props = tmp_path / "Ghidra" / "application.properties"
        props.parent.mkdir(parents=True, exist_ok=True)
        props.write_text(version_line)
        return tmp_path

    def test_reads_major_from_full_version(self, tmp_path):
        install = self._make_install(tmp_path, "application.version=12.1.2\n")
        assert _read_ghidra_major_version(install) == 12

    def test_reads_major_for_ghidra_11(self, tmp_path):
        install = self._make_install(tmp_path, "application.version=11.3.1\n")
        assert _read_ghidra_major_version(install) == 11

    def test_ignores_surrounding_properties(self, tmp_path):
        body = "application.name=Ghidra\napplication.version = 12.0\nfoo=bar\n"
        install = self._make_install(tmp_path, body)
        assert _read_ghidra_major_version(install) == 12

    def test_none_install_dir_returns_none(self):
        assert _read_ghidra_major_version(None) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert _read_ghidra_major_version(tmp_path) is None

    def test_unparseable_version_returns_none(self, tmp_path):
        install = self._make_install(tmp_path, "application.version=dev\n")
        assert _read_ghidra_major_version(install) is None


# ---------------------------------------------------------------------------
# _assert_ghidra_safe_project_dir -- gated to Ghidra 12+
# ---------------------------------------------------------------------------
class TestAssertGhidraSafeProjectDir:
    DOTTED = Path.home() / ".local" / "share" / "pyghidra-lite" / "projects"
    CLEAN = Path.home() / "pyghidra-lite" / "projects"

    # --- Ghidra 12+: dot-leading components are rejected ---
    def test_rejects_dotted_dir_on_ghidra_12(self):
        with pytest.raises(ValueError, match=r"starting with '\.'"):
            _assert_ghidra_safe_project_dir(self.DOTTED, 12)

    def test_rejects_dotted_dir_on_ghidra_13(self):
        with pytest.raises(ValueError):
            _assert_ghidra_safe_project_dir(self.DOTTED, 13)

    def test_error_names_the_offending_component(self):
        with pytest.raises(ValueError, match=r"\.local"):
            _assert_ghidra_safe_project_dir(self.DOTTED, 12)

    def test_allows_clean_dir_on_ghidra_12(self):
        _assert_ghidra_safe_project_dir(self.CLEAN, 12)  # no raise

    # --- Ghidra 11.x and earlier: the restriction does not exist ---
    def test_allows_dotted_dir_on_ghidra_11(self):
        _assert_ghidra_safe_project_dir(self.DOTTED, 11)  # no raise

    # --- Unknown version: skip rather than risk a false positive ---
    def test_skips_check_when_version_unknown(self):
        _assert_ghidra_safe_project_dir(self.DOTTED, None)  # no raise

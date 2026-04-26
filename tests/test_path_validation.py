"""Tests for path validation security boundary.

Covers parse_analysis_id(), _validate_project_id(), _safe_project_path(),
and the hardened _read_status_file / _write_status_file / _write_job_result.
"""

from pathlib import Path

import pytest

from pyghidra_lite.backend import parse_analysis_id
from pyghidra_lite import server


# ---------------------------------------------------------------------------
# parse_analysis_id
# ---------------------------------------------------------------------------

class TestParseAnalysisId:
    def test_valid_fast(self):
        assert parse_analysis_id("abcdef0123456789-fast") == ("abcdef0123456789", "fast")

    def test_valid_default(self):
        assert parse_analysis_id("0000000000000000-default") == ("0000000000000000", "default")

    def test_valid_deep(self):
        assert parse_analysis_id("ffffffffffffffff-deep") == ("ffffffffffffffff", "deep")

    def test_rejects_traversal(self):
        assert parse_analysis_id("../../etc-fast") is None

    def test_rejects_short_hex(self):
        assert parse_analysis_id("abcdef-fast") is None

    def test_rejects_long_hex(self):
        assert parse_analysis_id("abcdef01234567890-fast") is None

    def test_rejects_uppercase(self):
        assert parse_analysis_id("ABCDEF0123456789-fast") is None

    def test_rejects_no_suffix(self):
        assert parse_analysis_id("abcdef0123456789") is None

    def test_rejects_unknown_suffix(self):
        assert parse_analysis_id("abcdef0123456789-turbo") is None

    def test_rejects_empty(self):
        assert parse_analysis_id("") is None

    def test_rejects_dots_suffix(self):
        assert parse_analysis_id("../../../tmp-deep") is None


# ---------------------------------------------------------------------------
# _validate_project_id
# ---------------------------------------------------------------------------

class TestValidateProjectId:
    def test_accepts_unit_id(self):
        server._validate_project_id("abcdef0123456789")

    def test_accepts_analysis_id_fast(self):
        server._validate_project_id("abcdef0123456789-fast")

    def test_accepts_analysis_id_default(self):
        server._validate_project_id("abcdef0123456789-default")

    def test_accepts_analysis_id_deep(self):
        server._validate_project_id("abcdef0123456789-deep")

    def test_rejects_traversal(self):
        with pytest.raises(ValueError, match="Invalid project_id"):
            server._validate_project_id("../../etc")

    def test_rejects_traversal_with_suffix(self):
        with pytest.raises(ValueError, match="Invalid project_id"):
            server._validate_project_id("../../etc-fast")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="Invalid project_id"):
            server._validate_project_id("")

    def test_rejects_plain_name(self):
        with pytest.raises(ValueError, match="Invalid project_id"):
            server._validate_project_id("testunit")

    def test_rejects_uppercase_hex(self):
        with pytest.raises(ValueError, match="Invalid project_id"):
            server._validate_project_id("ABCDEF0123456789")


# ---------------------------------------------------------------------------
# _safe_project_path
# ---------------------------------------------------------------------------

class TestSafeProjectPath:
    def test_returns_resolved_path(self, tmp_path):
        result = server._safe_project_path(tmp_path, "abcdef0123456789")
        assert result == (tmp_path / "abcdef0123456789").resolve()

    def test_rejects_invalid_id(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid project_id"):
            server._safe_project_path(tmp_path, "../hack")

    def test_rejects_traversal_suffix(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid project_id"):
            server._safe_project_path(tmp_path, "../../etc-fast")


# ---------------------------------------------------------------------------
# _read_status_file / _write_status_file / _write_job_result
# ---------------------------------------------------------------------------

class TestPathHelperValidation:
    @pytest.fixture(autouse=True)
    def _cfg(self, tmp_path, monkeypatch):
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        self.project_dir = tmp_path

    def test_read_status_file_returns_empty_for_invalid_id(self):
        assert server._read_status_file("../malicious") == {}

    def test_read_status_file_returns_empty_for_empty_id(self):
        assert server._read_status_file("") == {}

    def test_write_status_file_rejects_invalid_id(self):
        with pytest.raises(ValueError):
            server._write_status_file("../malicious", {"status": "complete"})

    def test_write_job_result_rejects_invalid_id(self):
        with pytest.raises(ValueError):
            server._write_job_result("not-a-hex-id", {"result": "data"})

    def test_write_job_result_rejects_analysis_id(self):
        with pytest.raises(ValueError):
            server._write_job_result("abcdef0123456789-fast", {"result": "data"})

    def test_write_job_result_accepts_valid_hex(self):
        server._write_job_result("abcdef0123456789", {"result": "data"})
        result_file = self.project_dir / "abcdef0123456789" / "result.json"
        assert result_file.exists()

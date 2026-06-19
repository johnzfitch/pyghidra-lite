"""Tests for _find_on_disk() cache/tombstone semantics.

Pure-Python: _iter_disk_status is mocked, so no JVM is started.

The key behavior under test (PR: stop tombstoning errored analyses):
  - status=='complete'           -> return / collect the record (cache hit)
  - status in (analyzing, queued)-> raise ValueError (caller polls for progress)
  - status=='error'              -> treated as "no usable cache": None / skipped,
                                    so the caller can re-import (no permanent tombstone)
  - anything else (missing/corrupt status) -> raise (surface, don't swallow)
"""

import pytest

from pyghidra_lite import server

ANALYSIS_ID = "abcdef0123456789-fast"
UNIT_ID = "abcdef0123456789"


@pytest.fixture(autouse=True)
def _cfg(tmp_path, monkeypatch):
    # _find_on_disk early-returns None unless the projects dir exists.
    monkeypatch.setattr(server, "_server_config", server.ServerConfig(project_dir=tmp_path))


def _mock_disk(monkeypatch, *records):
    """Make _iter_disk_status yield (project_id, data) for the given record dicts."""
    pairs = [(rec.get("analysis_id", "proj"), rec) for rec in records]
    monkeypatch.setattr(server, "_iter_disk_status", lambda: iter(pairs))


# ---------------------------------------------------------------------------
# analysis_id branch
# ---------------------------------------------------------------------------
class TestFindOnDiskByAnalysisId:
    def test_complete_returns_record(self, monkeypatch):
        rec = {"analysis_id": ANALYSIS_ID, "unit_id": UNIT_ID, "status": "complete"}
        _mock_disk(monkeypatch, rec)
        assert server._find_on_disk(ANALYSIS_ID) is rec

    def test_error_returns_none_not_tombstone(self, monkeypatch):
        # The whole point of the fix: an errored record is re-importable, not a wall.
        rec = {"analysis_id": ANALYSIS_ID, "unit_id": UNIT_ID, "status": "error"}
        _mock_disk(monkeypatch, rec)
        assert server._find_on_disk(ANALYSIS_ID) is None

    def test_analyzing_raises_for_polling(self, monkeypatch):
        rec = {"analysis_id": ANALYSIS_ID, "unit_id": UNIT_ID, "status": "analyzing"}
        _mock_disk(monkeypatch, rec)
        with pytest.raises(ValueError, match="status='analyzing'"):
            server._find_on_disk(ANALYSIS_ID)

    def test_queued_raises_for_polling(self, monkeypatch):
        rec = {"analysis_id": ANALYSIS_ID, "unit_id": UNIT_ID, "status": "queued"}
        _mock_disk(monkeypatch, rec)
        with pytest.raises(ValueError, match="status='queued'"):
            server._find_on_disk(ANALYSIS_ID)

    def test_unexpected_status_raises(self, monkeypatch):
        rec = {"analysis_id": ANALYSIS_ID, "unit_id": UNIT_ID, "status": "frobnicated"}
        _mock_disk(monkeypatch, rec)
        with pytest.raises(ValueError, match="unexpected status"):
            server._find_on_disk(ANALYSIS_ID)

    def test_missing_status_raises(self, monkeypatch):
        rec = {"analysis_id": ANALYSIS_ID, "unit_id": UNIT_ID}  # no 'status'
        _mock_disk(monkeypatch, rec)
        with pytest.raises(ValueError, match="unexpected status"):
            server._find_on_disk(ANALYSIS_ID)


# ---------------------------------------------------------------------------
# unit_id branch
# ---------------------------------------------------------------------------
class TestFindOnDiskByUnitId:
    def test_complete_returns_record(self, monkeypatch):
        rec = {"unit_id": UNIT_ID, "status": "complete"}
        _mock_disk(monkeypatch, rec)
        assert server._find_on_disk(UNIT_ID) is rec

    def test_error_is_skipped_returns_none(self, monkeypatch):
        # Errored record is skipped -> no matches -> None (re-importable).
        rec = {"unit_id": UNIT_ID, "status": "error"}
        _mock_disk(monkeypatch, rec)
        assert server._find_on_disk(UNIT_ID) is None

    def test_analyzing_raises_for_polling(self, monkeypatch):
        rec = {"unit_id": UNIT_ID, "status": "analyzing"}
        _mock_disk(monkeypatch, rec)
        with pytest.raises(ValueError, match="status='analyzing'"):
            server._find_on_disk(UNIT_ID)

    def test_unexpected_status_raises(self, monkeypatch):
        rec = {"unit_id": UNIT_ID, "status": "frobnicated"}
        _mock_disk(monkeypatch, rec)
        with pytest.raises(ValueError, match="unexpected status"):
            server._find_on_disk(UNIT_ID)

    def test_errored_then_complete_returns_complete(self, monkeypatch):
        # A stale errored record must not shadow a good completed one for the same unit.
        bad = {"unit_id": UNIT_ID, "status": "error"}
        good = {"unit_id": UNIT_ID, "status": "complete"}
        _mock_disk(monkeypatch, bad, good)
        assert server._find_on_disk(UNIT_ID) is good

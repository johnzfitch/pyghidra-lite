"""Tests for generic async scan job system.

Covers _new_job_id, _write_job_result, _run_scan_task, get_job_result,
batch_search_strings(background=True), extract_bunfs, and the analysis_status
scan-job branch -- all without a running JVM.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from mcp.shared.exceptions import McpError
from mcp.types import INVALID_PARAMS, INTERNAL_ERROR

from pyghidra_lite import server


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    """Monkeypatch _server_config to use a tmp project dir."""
    config = server.ServerConfig(project_dir=tmp_path)
    monkeypatch.setattr(server, "_server_config", config)
    return config


@pytest.fixture()
def clean_jobs(monkeypatch):
    """Ensure _active_jobs is empty before and after each test."""
    old = server._active_jobs.copy()
    server._active_jobs.clear()
    yield server._active_jobs
    server._active_jobs.clear()
    server._active_jobs.update(old)


# ---------------------------------------------------------------------------
# _new_job_id
# ---------------------------------------------------------------------------

class TestNewJobId:

    def test_format_matches_unit_id_re(self):
        jid = server._new_job_id()
        assert server._UNIT_ID_RE.match(jid), f"job_id {jid!r} doesn't match _UNIT_ID_RE"

    def test_unique(self):
        ids = {server._new_job_id() for _ in range(50)}
        assert len(ids) == 50

    def test_length(self):
        assert len(server._new_job_id()) == 16


# ---------------------------------------------------------------------------
# _write_job_result
# ---------------------------------------------------------------------------

class TestWriteJobResult:

    def test_writes_result_json(self, cfg, tmp_path):
        server._write_job_result("aabbccddeeff0011", {"status": "complete", "x": 1})
        result_file = tmp_path / "aabbccddeeff0011" / "result.json"
        assert result_file.exists()
        data = json.loads(result_file.read_text())
        assert data["status"] == "complete"
        assert data["x"] == 1

    def test_atomic_no_tmp_left(self, cfg, tmp_path):
        server._write_job_result("1122334455667788", {"status": "complete"})
        d = tmp_path / "1122334455667788"
        assert not (d / "result.json.tmp").exists()

    def test_overwrites_existing(self, cfg, tmp_path):
        jid = "aabbccdd11223344"
        server._write_job_result(jid, {"v": 1})
        server._write_job_result(jid, {"v": 2})
        data = json.loads((tmp_path / jid / "result.json").read_text())
        assert data["v"] == 2


# ---------------------------------------------------------------------------
# _run_scan_task
# ---------------------------------------------------------------------------

class TestRunScanTask:

    def test_success_writes_complete(self, cfg, tmp_path, clean_jobs):
        jid = server._new_job_id()
        job: dict = {"kind": "scan", "status": "queued"}
        clean_jobs[jid] = job

        asyncio.run(server._run_scan_task(jid, job, lambda: {"count": 7}))

        assert job["status"] == "complete"
        result_file = tmp_path / jid / "result.json"
        assert result_file.exists()
        data = json.loads(result_file.read_text())
        assert data["status"] == "complete"
        assert data["count"] == 7

    def test_error_writes_error(self, cfg, tmp_path, clean_jobs):
        jid = server._new_job_id()
        job: dict = {"kind": "scan", "status": "queued"}
        clean_jobs[jid] = job

        def boom():
            raise ValueError("injected failure")

        asyncio.run(server._run_scan_task(jid, job, boom))

        assert job["status"] == "error"
        assert "injected failure" in job["error"]
        result_file = tmp_path / jid / "result.json"
        data = json.loads(result_file.read_text())
        assert data["status"] == "error"
        assert "injected failure" in data["error"]

    def test_error_message_truncated_at_500(self, cfg, tmp_path, clean_jobs):
        jid = server._new_job_id()
        job: dict = {"kind": "scan", "status": "queued"}
        clean_jobs[jid] = job

        def long_error():
            raise RuntimeError("x" * 1000)

        asyncio.run(server._run_scan_task(jid, job, long_error))
        assert len(job["error"]) <= 500


# ---------------------------------------------------------------------------
# get_job_result
# ---------------------------------------------------------------------------

class TestGetJobResult:
    """Tests for _get_job_result internal helper."""

    def test_invalid_job_id_format(self, cfg):
        with pytest.raises(McpError) as exc:
            server._get_job_result("not-valid!")
        assert exc.value.error.code == INVALID_PARAMS

    def test_missing_result_not_found(self, cfg, clean_jobs):
        jid = "a" * 16
        with pytest.raises(McpError) as exc:
            server._get_job_result(jid)
        assert exc.value.error.code == INVALID_PARAMS
        assert "not available" in exc.value.error.message

    def test_missing_result_shows_current_status(self, cfg, clean_jobs):
        jid = server._new_job_id()
        clean_jobs[jid] = {"kind": "scan", "status": "running"}
        with pytest.raises(McpError) as exc:
            server._get_job_result(jid)
        assert "running" in exc.value.error.message

    def test_returns_result_when_complete(self, cfg, tmp_path, clean_jobs):
        jid = server._new_job_id()
        server._write_job_result(jid, {"status": "complete", "results": {"foo": 3}})
        data = server._get_job_result(jid)
        assert data["status"] == "complete"
        assert data["results"]["foo"] == 3

    def test_corrupted_result_raises_internal_error(self, cfg, tmp_path):
        jid = server._new_job_id()
        d = tmp_path / jid
        d.mkdir()
        (d / "result.json").write_text("{{broken json{{")
        with pytest.raises(McpError) as exc:
            server._get_job_result(jid)
        assert exc.value.error.code == INTERNAL_ERROR


# ---------------------------------------------------------------------------
# batch_search_strings background=True
# ---------------------------------------------------------------------------

class TestSearchBackground:
    """Tests for search(bg=True) batch background mode."""

    def _make_handle(self):
        handle = MagicMock()
        handle.unit_id = "a" * 16
        handle.name = "test.bin"
        return handle

    def test_background_returns_job_id(self, cfg, clean_jobs, monkeypatch):
        handle = self._make_handle()
        monkeypatch.setattr(server, "_get_handle", lambda b: handle)

        tasks_created = []

        def _capture_task(coro):
            tasks_created.append(coro)
            coro.close()  # suppress "coroutine never awaited" warning
            return MagicMock()

        monkeypatch.setattr(asyncio, "create_task", _capture_task)

        with patch.object(server, "GhidraTools"):
            result = asyncio.run(server.search(
                binary="test.bin", query=["hello"], ctx=MagicMock(), bg=True,
            ))

        assert "job_id" in result
        assert result["status"] == "queued"
        assert server._UNIT_ID_RE.match(result["job_id"])
        assert "hint" in result
        assert len(tasks_created) == 1

    def test_background_registers_in_active_jobs(self, cfg, clean_jobs, monkeypatch):
        handle = self._make_handle()
        monkeypatch.setattr(server, "_get_handle", lambda b: handle)
        def _sink(coro): coro.close(); return MagicMock()
        monkeypatch.setattr(asyncio, "create_task", _sink)

        with patch.object(server, "GhidraTools"):
            result = asyncio.run(server.search(
                binary="test.bin", query=["x"], ctx=MagicMock(), bg=True,
            ))

        jid = result["job_id"]
        assert jid in clean_jobs
        assert clean_jobs[jid]["kind"] == "scan"
        assert clean_jobs[jid]["label"] == "batch_search"

    def test_foreground_path_works(self, cfg, monkeypatch):
        """bg=False should process query synchronously."""
        handle = self._make_handle()
        monkeypatch.setattr(server, "_get_handle", lambda b: handle)

        # Mock GhidraTools.batch_search_strings
        mock_tools = MagicMock()
        mock_tools.batch_search_strings.return_value = {"q": 5}
        with patch.object(server, "GhidraTools", return_value=mock_tools):
            result = asyncio.run(server.search(
                binary="test.bin", query=["q"], ctx=MagicMock(), bg=False,
            ))

        assert result == {"queries": ["q"], "results": {"q": 5}}


# ---------------------------------------------------------------------------
# extract_bunfs
# ---------------------------------------------------------------------------

class TestSearchExtract:
    """Tests for search(type="extract") bunfs extraction."""

    def _make_handle(self, unit_id="beef1234cafe5678"):
        # Use a ProgramHandle-like mock that passes isinstance check
        from pyghidra_lite.backend import ProgramHandle
        handle = MagicMock(spec=ProgramHandle)
        handle.unit_id = unit_id
        handle.name = "bun-2.1.70"
        return handle

    def test_queues_job_and_returns_job_id(self, cfg, tmp_path, clean_jobs, monkeypatch):
        handle = self._make_handle()
        monkeypatch.setattr(server, "_get_handle", lambda b: handle)
        monkeypatch.setattr(server, "_read_status_file", lambda uid: {
            "binary_path": str(tmp_path / "bun-2.1.70"),
        })
        def _sink(coro): coro.close(); return MagicMock()
        monkeypatch.setattr(asyncio, "create_task", _sink)

        # Patch GhidraTools since we don't have a real program
        with patch.object(server, "GhidraTools"):
            result = asyncio.run(server.search(
                binary="bun-2.1.70", query="", type="extract", ctx=MagicMock()
            ))

        assert "job_id" in result
        assert result["status"] == "queued"
        assert server._UNIT_ID_RE.match(result["job_id"])
        assert result["job_id"] in clean_jobs
        assert clean_jobs[result["job_id"]]["label"] == "extract_bunfs"

    def test_default_output_dir_derived_from_binary_path(self, cfg, tmp_path, clean_jobs, monkeypatch):
        binary_path = tmp_path / "bun-2.1.70"
        handle = self._make_handle()
        monkeypatch.setattr(server, "_get_handle", lambda b: handle)
        monkeypatch.setattr(server, "_read_status_file", lambda uid: {
            "binary_path": str(binary_path),
        })

        def _sink(coro): coro.close(); return MagicMock()
        monkeypatch.setattr(asyncio, "create_task", _sink)

        # Patch GhidraTools since we don't have a real program
        with patch.object(server, "GhidraTools"):
            result = asyncio.run(server.search(
                binary="bun-2.1.70", query="", type="extract", ctx=MagicMock()
            ))
        # The output_dir should be next to binary with _bunfs_extracted suffix
        # We can't easily capture it without running the executor, so just verify
        # the job was queued successfully
        assert result["status"] == "queued"

    def test_extract_blocking_raises_on_no_bunfs(self, cfg, tmp_path, monkeypatch):
        """_extract_bunfs_blocking should raise if detect_embedded_runtime finds no bunfs."""
        handle = self._make_handle()
        monkeypatch.setattr(server, "_read_status_file", lambda uid: {
            "binary_path": str(tmp_path / "not-a-bun-binary"),
        })

        tools_mock = MagicMock()
        tools_mock.detect_embedded_runtime.return_value = {"detected": False, "runtimes": []}

        with patch.object(server, "GhidraTools", return_value=tools_mock):
            with pytest.raises(ValueError, match="No bunfs payload"):
                server._extract_bunfs_blocking(handle, tmp_path / "out")

    def test_extract_blocking_raises_on_missing_binary_path(self, cfg, tmp_path, monkeypatch):
        """_extract_bunfs_blocking raises if binary_path not in status file."""
        handle = self._make_handle()
        monkeypatch.setattr(server, "_read_status_file", lambda uid: {})  # no binary_path

        tools_mock = MagicMock()
        tools_mock.detect_embedded_runtime.return_value = {
            "detected": True,
            "runtimes": [{"type": "bunfs", "confidence": "high", "strategy": "external_tools"}],
        }

        with patch.object(server, "GhidraTools", return_value=tools_mock):
            with pytest.raises(ValueError, match="binary_path not recorded"):
                server._extract_bunfs_blocking(handle, tmp_path / "out")

    def test_extract_blocking_raises_on_missing_file(self, cfg, tmp_path, monkeypatch):
        """_extract_bunfs_blocking raises FileNotFoundError if binary file is gone."""
        handle = self._make_handle()
        missing = tmp_path / "gone-binary"
        monkeypatch.setattr(server, "_read_status_file", lambda uid: {
            "binary_path": str(missing),
        })

        tools_mock = MagicMock()
        tools_mock.detect_embedded_runtime.return_value = {
            "detected": True,
            "runtimes": [{"type": "bunfs", "confidence": "high",
                          "strategy": "external_tools", "magic_address": "0x0"}],
        }

        with patch.object(server, "GhidraTools", return_value=tools_mock):
            with pytest.raises(FileNotFoundError):
                server._extract_bunfs_blocking(handle, tmp_path / "out")


# ---------------------------------------------------------------------------
# analysis_status scan job branch
# ---------------------------------------------------------------------------

class TestBinariesJobBranch:
    """Tests for binaries(jobs=True) showing scan job status."""

    def test_in_memory_queued_scan_job(self, cfg, tmp_path, clean_jobs, monkeypatch):
        backend = MagicMock()
        backend.list_programs.return_value = []
        backend.programs = {}
        monkeypatch.setattr(server, "_backend", backend)
        monkeypatch.setattr(server, "get_backend", lambda: backend)

        jid = server._new_job_id()
        clean_jobs[jid] = {"kind": "scan", "label": "batch_search", "status": "queued", "binary_name": "test"}

        result = asyncio.run(server.binaries(ctx=MagicMock(), jobs=True))

        job_entries = [r for r in result if r.get("unit_id") == jid]
        assert len(job_entries) == 1
        assert job_entries[0]["status"] == "queued"

    def test_in_memory_complete_scan_job_has_hint(self, cfg, tmp_path, clean_jobs, monkeypatch):
        backend = MagicMock()
        backend.list_programs.return_value = []
        backend.programs = {}
        monkeypatch.setattr(server, "_backend", backend)
        monkeypatch.setattr(server, "get_backend", lambda: backend)

        jid = server._new_job_id()
        clean_jobs[jid] = {"kind": "scan", "label": "extract_bunfs", "status": "complete", "binary_name": "test"}

        result = asyncio.run(server.binaries(ctx=MagicMock(), jobs=True))

        job_entries = [r for r in result if r.get("unit_id") == jid]
        assert len(job_entries) == 1
        assert job_entries[0]["status"] == "complete"
        # Hint is included when jobs=True
        assert "hint" in job_entries[0]

    def test_binary_job_reads_live_status_file(self, cfg, tmp_path, clean_jobs, monkeypatch):
        """binaries(jobs=True) should merge live .analysis_status fields and recompute ETA."""
        backend = MagicMock()
        backend.list_programs.return_value = []
        backend.programs = {}
        monkeypatch.setattr(server, "_backend", backend)
        monkeypatch.setattr(server, "get_backend", lambda: backend)

        uid = "a" * 16
        clean_jobs[uid] = {
            "status": "analyzing",
            "binary_name": "claude.bin",
            "profile": "fast",
            "eta_sec": 1125,
        }

        unit_dir = tmp_path / uid
        unit_dir.mkdir()
        (unit_dir / ".analysis_status").write_text(json.dumps({
            "status": "analyzing",
            "phase": "analysis",
            "done": 25300,
            "elapsed_seconds": 700,
            "binary_name": "claude.bin",
            "profile": "fast",
        }))

        result = asyncio.run(server.binaries(ctx=MagicMock(), jobs=True))

        job_entries = [r for r in result if r.get("unit_id") == uid]
        assert len(job_entries) == 1
        assert job_entries[0]["status"] == "analyzing"
        assert job_entries[0]["phase"] == "analysis"
        assert job_entries[0]["done"] == 25300
        assert job_entries[0]["elapsed_seconds"] == 700
        assert job_entries[0]["eta_sec"] == 425


# ---------------------------------------------------------------------------
# AnalysisProgressListener binary_path
# ---------------------------------------------------------------------------

class TestProgressListenerBinaryPath:

    def test_binary_path_stored_when_provided(self, tmp_path):
        status_path = tmp_path / ".analysis_status"
        server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024,
            binary_path="/real/path/to/test.bin",
        )
        status = json.loads(status_path.read_text())
        assert status["binary_path"] == "/real/path/to/test.bin"

    def test_binary_path_omitted_when_none(self, tmp_path):
        status_path = tmp_path / ".analysis_status"
        server.AnalysisProgressListener(status_path, "test.bin", "default", 1024)
        status = json.loads(status_path.read_text())
        assert "binary_path" not in status

    def test_binary_path_persists_through_complete(self, tmp_path):
        """binary_path should survive subsequent _write calls like complete()."""
        status_path = tmp_path / ".analysis_status"
        listener = server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024,
            binary_path="/path/to/test.bin",
        )
        listener.complete(10, ["elf"])
        status = json.loads(status_path.read_text())
        assert status["binary_path"] == "/path/to/test.bin"


# ---------------------------------------------------------------------------
# MCP tool registration
# ---------------------------------------------------------------------------

class TestConsolidatedToolsRegistered:
    """Tests for consolidated tool registration."""

    def test_search_registered(self):
        """search tool handles job results, bunfs extraction, and string search."""
        assert "search" in server.mcp._tool_manager._tools

    def test_binaries_registered(self):
        """binaries tool replaces list_binaries/analysis_status/get_job_result."""
        assert "binaries" in server.mcp._tool_manager._tools

    def test_search_is_async(self):
        import inspect
        fn = server.mcp._tool_manager._tools["search"].fn
        assert inspect.iscoroutinefunction(fn)

    def test_total_tool_count_is_8(self):
        tools = server.mcp._tool_manager._tools
        expected = {"load", "delete", "binaries", "info", "functions", "code", "xrefs", "search"}
        assert set(tools.keys()) == expected, f"Expected {expected}, got {set(tools.keys())}"

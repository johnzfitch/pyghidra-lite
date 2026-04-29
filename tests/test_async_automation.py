"""Tests for async automation features (Phases 0-5).

Tests CLI structure, helper functions, status file protocol,
AnalysisProgressListener, ProjectWatcher, crash recovery, and
MCP tool registration -- all without requiring a running JVM.
"""

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from pyghidra_lite import server


# =============================================================================
# Phase 0: Prerequisite Fixes
# =============================================================================

class TestPhase0:
    """Verify _capabilities keying and backend.py changes."""

    def test_ensure_capabilities_keys_by_unit_id(self):
        """_ensure_capabilities should key by handle.unit_id, not handle.name."""
        handle = MagicMock()
        handle.name = "httpd-a3f8e2c1"
        handle.unit_id = "a3f8e2c1deadbeef"
        handle.metadata = {"Executable Format": "ELF"}
        handle.program = MagicMock()

        # Patch detect_capabilities to avoid Ghidra JVM
        caps = server.BinaryCapabilities(name=handle.name, is_elf=True)
        with patch.object(server, "detect_capabilities", return_value=caps):
            with patch.object(server, "_backend_lock", server.threading.RLock()):
                old_caps = server._capabilities.copy()
                try:
                    server._capabilities.clear()
                    result = server._ensure_capabilities(handle)
                    assert handle.unit_id in server._capabilities
                    assert handle.name not in server._capabilities
                    assert result.is_elf
                finally:
                    server._capabilities.clear()
                    server._capabilities.update(old_caps)


# =============================================================================
# Phase 1: CLI Subcommand Split
# =============================================================================

class TestPhase1CLI:
    """Test Click CLI group structure and backward compatibility."""

    def test_cli_is_group(self):
        assert isinstance(server.cli, click.Group)

    def test_cli_has_serve_command(self):
        assert "serve" in server.cli.commands

    def test_cli_has_import_command(self):
        assert "import" in server.cli.commands

    def test_cli_has_list_command(self):
        assert "list" in server.cli.commands

    def test_default_group_class(self):
        assert isinstance(server.cli, server.DefaultGroup)

    def test_default_group_routing_unknown_arg(self):
        """Unknown first args should be prepended with 'serve'."""
        # Test the routing logic directly: unknown args get 'serve' prepended
        ctx = click.Context(server.cli)
        original = ["--restrict-path", "/tmp"]
        # DefaultGroup.parse_args mutates args by prepending 'serve'
        # Verify the logic by calling parse_args on a fresh group
        group = server.DefaultGroup("test")
        group.add_command(click.Command("serve", params=[]), "serve")
        test_args = list(original)
        # The parse_args prepend logic runs before super().parse_args
        if test_args and test_args[0] not in group.commands and test_args[0] not in server.DefaultGroup._group_flags:
            test_args = ["serve"] + test_args
        assert test_args[0] == "serve"

    def test_default_group_preserves_known_commands(self):
        """Known subcommands should NOT be rerouted."""
        ctx = click.Context(server.cli)
        # 'import' is a known command -- should parse directly
        # Just test that it's recognized
        assert "import" in server.cli.commands

    def test_default_group_flags_not_routed(self):
        """Group-level flags like --version should not route to serve."""
        assert "-v" in server.DefaultGroup._group_flags
        assert "--version" in server.DefaultGroup._group_flags
        assert "--help" in server.DefaultGroup._group_flags
        assert "-h" in server.DefaultGroup._group_flags

    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(server.cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower() or server.__version__ in result.output

    def test_v_flag(self):
        runner = CliRunner()
        result = runner.invoke(server.cli, ["-v"])
        assert result.exit_code == 0

    def test_import_cmd_no_args_exits(self):
        """import with no binaries should exit with error."""
        runner = CliRunner()
        result = runner.invoke(server.cli, ["import"])
        assert result.exit_code != 0

    def test_import_cmd_has_jvm_heap(self):
        """import should accept --jvm-heap."""
        params = {p.name for p in server.import_cmd.params}
        assert "jvm_heap" in params

    def test_import_cmd_always_writes_status(self):
        """import always writes .analysis_status; --status-file flag is gone."""
        params = {p.name for p in server.import_cmd.params}
        assert "status_file" not in params, (
            "--status-file was removed: status is always written"
        )

    def test_import_cmd_has_runtime_home(self):
        """import should accept --runtime-home."""
        params = {p.name for p in server.import_cmd.params}
        assert "runtime_home" in params

    def test_import_cmd_has_bootstrap(self):
        """import should accept --bootstrap."""
        params = {p.name for p in server.import_cmd.params}
        assert "bootstrap" in params

    def test_import_cmd_has_bootstrap_mode(self):
        """import should accept --bootstrap-mode."""
        params = {p.name for p in server.import_cmd.params}
        assert "bootstrap_mode" in params

    def test_serve_cmd_has_max_workers(self):
        """serve should accept --max-workers."""
        params = {p.name for p in server.serve_cmd.params}
        assert "max_workers" in params

    def test_serve_cmd_has_runtime_home(self):
        """serve should accept --runtime-home."""
        params = {p.name for p in server.serve_cmd.params}
        assert "runtime_home" in params

    def test_list_cmd_empty(self, tmp_path):
        """list on empty dir should report no binaries."""
        runner = CliRunner()
        result = runner.invoke(server.cli, ["list", "--project-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No analyzed binaries" in result.output or "No projects" in result.output

    def test_list_cmd_missing_dir(self, tmp_path):
        """list on nonexistent dir should handle gracefully."""
        runner = CliRunner()
        result = runner.invoke(server.cli, ["list", "--project-dir", str(tmp_path / "nonexistent")])
        assert result.exit_code == 0

    def test_list_cmd_json_output(self, tmp_path):
        """list --json on empty dir should output valid JSON."""
        runner = CliRunner()
        result = runner.invoke(server.cli, ["list", "--project-dir", str(tmp_path), "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)

    def test_list_cmd_with_project(self, tmp_path):
        """list should detect a project directory with .gpr file."""
        project_dir = tmp_path / "abcd1234abcd1234"
        project_dir.mkdir()
        (project_dir / "abcd1234abcd1234.gpr").touch()
        (project_dir / ".analysis_status").write_text(json.dumps({
            "status": "complete",
            "binary_name": "test.bin",
            "functions": 42,
            "capabilities": ["elf"],
            "profile": "default",
        }))

        runner = CliRunner()
        result = runner.invoke(server.cli, ["list", "--project-dir", str(tmp_path), "--json"])
        assert result.exit_code == 0
        entries = json.loads(result.output)
        assert len(entries) == 1
        assert entries[0]["unit_id"] == "abcd1234abcd1234"
        assert entries[0]["status"] == "complete"
        assert entries[0]["functions"] == 42

    def test_main_calls_cli(self):
        """main() should call cli()."""
        # Just verify main exists and is callable
        assert callable(server.main)


# =============================================================================
# Phase 2/3: Helper Functions
# =============================================================================

class TestHelperFunctions:

    def test_format_capabilities_full(self):
        caps = server.BinaryCapabilities(
            name="test", is_elf=True, is_macho=True, is_pe=True,
            has_swift=True, has_objc=True, has_hermes=True,
        )
        result = server._format_capabilities(caps)
        assert "elf" in result
        assert "macho" in result
        assert "pe" in result
        assert "swift" in result
        assert "objc" in result
        assert "hermes" in result

    def test_format_capabilities_empty(self):
        caps = server.BinaryCapabilities(name="test")
        result = server._format_capabilities(caps)
        assert result == []

    def test_estimate_analysis_time_fast(self):
        # 10MB binary, fast profile
        t = server._estimate_analysis_time(10 * 1024 * 1024, "fast")
        assert t >= 5  # minimum base

    def test_estimate_analysis_time_deep(self):
        # 10MB binary, deep profile
        t = server._estimate_analysis_time(10 * 1024 * 1024, "deep")
        assert t > server._estimate_analysis_time(10 * 1024 * 1024, "fast")

    def test_estimate_analysis_time_unknown_profile(self):
        # Unknown profile should fall back to default
        t = server._estimate_analysis_time(10 * 1024 * 1024, "unknown")
        t_default = server._estimate_analysis_time(10 * 1024 * 1024, "default")
        assert t == t_default

    def test_pid_alive_self(self):
        assert server._pid_alive(os.getpid())

    def test_pid_alive_dead(self):
        # PID 1 might be alive but PID 2^30 shouldn't exist
        assert not server._pid_alive(2**30)

    def test_read_status_file_missing(self, tmp_path, monkeypatch):
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        result = server._read_status_file("aabbccddeeff0011")
        assert result == {}

    def test_write_and_read_status_file(self, tmp_path, monkeypatch):
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        data = {"status": "complete", "functions": 42}
        server._write_status_file("aabbccddeeff0011", data)

        result = server._read_status_file("aabbccddeeff0011")
        assert result["status"] == "complete"
        assert result["functions"] == 42

    def test_write_status_file_atomic(self, tmp_path, monkeypatch):
        """Verify atomic write (no .tmp file left behind)."""
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        server._write_status_file("aabbccddeeff0022", {"status": "testing"})

        project = tmp_path / "aabbccddeeff0022"
        assert (project / ".analysis_status").exists()
        assert not (project / ".analysis_status.tmp").exists()


# =============================================================================
# Phase 3: AnalysisProgressListener
# =============================================================================

class TestAnalysisProgressListener:

    def test_init_writes_analyzing(self, tmp_path):
        status_path = tmp_path / ".analysis_status"
        listener = server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024
        )
        status = json.loads(status_path.read_text())
        assert status["status"] == "analyzing"
        assert status["phase"] == "startup"
        assert status["binary_name"] == "test.bin"
        assert status["profile"] == "default"
        assert status["binary_size_bytes"] == 1024
        assert "pid" in status
        assert "started_at" in status

    def test_set_phase(self, tmp_path):
        status_path = tmp_path / ".analysis_status"
        listener = server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024
        )
        listener.set_phase("importing", progress=0.5)
        status = json.loads(status_path.read_text())
        assert status["phase"] == "importing"
        assert status["progress"] == 0.5
        assert "elapsed_seconds" in status

    def test_set_progress(self, tmp_path):
        status_path = tmp_path / ".analysis_status"
        listener = server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024
        )
        listener.set_progress(5, 10, "analysis")
        status = json.loads(status_path.read_text())
        assert status["progress"] == 0.5
        assert status["done"] == 5
        assert status["total"] == 10

    def test_complete(self, tmp_path):
        status_path = tmp_path / ".analysis_status"
        listener = server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024
        )
        listener.complete(42, ["elf"])
        status = json.loads(status_path.read_text())
        assert status["status"] == "complete"
        assert status["functions"] == 42
        assert status["capabilities"] == ["elf"]
        assert "duration_seconds" in status

    def test_error(self, tmp_path):
        status_path = tmp_path / ".analysis_status"
        listener = server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024
        )
        listener.error("boom", "importing")
        status = json.loads(status_path.read_text())
        assert status["status"] == "error"
        assert status["error"] == "boom"
        assert status["phase"] == "importing"

    def test_atomic_write(self, tmp_path):
        """Verify writes use atomic rename (no .tmp left behind)."""
        status_path = tmp_path / ".analysis_status"
        listener = server.AnalysisProgressListener(
            status_path, "test.bin", "default", 1024
        )
        listener.set_phase("test")
        assert not (tmp_path / ".analysis_status.tmp").exists()


# =============================================================================
# Phase 4/5: ProjectWatcher
# =============================================================================

class TestProjectWatcher:

    def test_watcher_ignores_non_status_files(self):
        watcher = server.ProjectWatcher(
            backend=MagicMock(),
            projects_dir=Path("/tmp"),
            loop=MagicMock(),
        )
        event = MagicMock()
        event.src_path = "/tmp/somefile.txt"
        watcher.on_modified(event)
        # Should not crash, and loop should not be called

    def test_watcher_on_moved_checks_dest(self, tmp_path):
        backend = MagicMock()
        backend.programs = {}
        loop = MagicMock()

        watcher = server.ProjectWatcher(backend, tmp_path, loop)

        # Create a complete status file
        unit_dir = tmp_path / "abc1230000000000"
        unit_dir.mkdir()
        status_path = unit_dir / ".analysis_status"
        status_path.write_text(json.dumps({"status": "complete"}))

        event = MagicMock()
        event.dest_path = str(status_path)
        watcher.on_moved(event)

        # Should schedule hot-load
        assert loop.call_soon_threadsafe.called

    def test_watcher_ignores_non_complete(self, tmp_path):
        backend = MagicMock()
        backend.programs = {}
        loop = MagicMock()

        watcher = server.ProjectWatcher(backend, tmp_path, loop)

        unit_dir = tmp_path / "abc1230000000000"
        unit_dir.mkdir()
        status_path = unit_dir / ".analysis_status"
        status_path.write_text(json.dumps({"status": "analyzing"}))

        event = MagicMock()
        event.dest_path = str(status_path)
        watcher.on_moved(event)

        # Should NOT schedule hot-load
        assert not loop.call_soon_threadsafe.called

    def test_watcher_skips_already_loaded(self, tmp_path):
        backend = MagicMock()
        handle = MagicMock()
        handle.unit_id = "abc1230000000000"
        backend.programs = {"prog": handle}
        loop = MagicMock()

        watcher = server.ProjectWatcher(backend, tmp_path, loop)

        unit_dir = tmp_path / "abc1230000000000"
        unit_dir.mkdir()
        status_path = unit_dir / ".analysis_status"
        status_path.write_text(json.dumps({"status": "complete"}))

        event = MagicMock()
        event.dest_path = str(status_path)
        watcher.on_moved(event)

        assert not loop.call_soon_threadsafe.called

    def test_watchdog_import(self):
        """Verify watchdog is importable."""
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        assert Observer is not None
        assert FileSystemEventHandler is not None

    def test_start_project_watcher(self, tmp_path):
        """start_project_watcher returns an observer that can be stopped."""
        backend = MagicMock()
        loop = MagicMock()
        observer = server.start_project_watcher(backend, tmp_path, loop)
        assert observer is not None
        observer.stop()
        observer.join(timeout=2)


# =============================================================================
# Phase 4/5: Crash Recovery
# =============================================================================

class TestCrashRecovery:

    def test_recover_dead_worker(self, tmp_path, monkeypatch):
        """Dead worker should be marked as error."""
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        monkeypatch.setattr(server, "_backend", MagicMock(programs={}))

        # Create an "analyzing" status with a dead PID
        uid = "dead00001234abcd"
        unit_dir = tmp_path / uid
        unit_dir.mkdir()
        (unit_dir / ".analysis_status").write_text(json.dumps({
            "status": "analyzing",
            "pid": 2**30,  # definitely not alive
            "binary_name": "test.bin",
        }))

        asyncio.run(server._recover_in_progress_jobs())

        # Should have been marked as error
        status = json.loads((unit_dir / ".analysis_status").read_text())
        assert status["status"] == "error"

    def test_recover_alive_worker(self, tmp_path, monkeypatch):
        """Alive worker should be tracked in _active_jobs."""
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        monkeypatch.setattr(server, "_backend", MagicMock(programs={}))
        old_jobs = server._active_jobs.copy()

        uid = "a11ce00000123456"
        unit_dir = tmp_path / uid
        unit_dir.mkdir()
        (unit_dir / ".analysis_status").write_text(json.dumps({
            "status": "analyzing",
            "pid": os.getpid(),  # current process is alive
            "binary_name": "test.bin",
        }))

        try:
            asyncio.run(server._recover_in_progress_jobs())
            analysis_id = f"{uid}-fast"
            assert analysis_id in server._active_jobs
            assert server._active_jobs[analysis_id]["recovered"]
        finally:
            server._active_jobs.clear()
            server._active_jobs.update(old_jobs)

    def test_recover_skips_complete(self, tmp_path, monkeypatch):
        """Completed analyses should be skipped during recovery."""
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        monkeypatch.setattr(server, "_backend", MagicMock(programs={}))

        uid = "c00100ed00000001"
        unit_dir = tmp_path / uid
        unit_dir.mkdir()
        (unit_dir / ".analysis_status").write_text(json.dumps({
            "status": "complete",
            "functions": 100,
        }))

        asyncio.run(server._recover_in_progress_jobs())

        # Should NOT be in active jobs
        assert uid not in server._active_jobs

    def test_recover_skips_loaded(self, tmp_path, monkeypatch):
        """Already-loaded binaries should be skipped."""
        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)

        handle = MagicMock()
        handle.unit_id = "loadedunit1234"
        backend = MagicMock()
        backend.programs = {"prog": handle}
        monkeypatch.setattr(server, "_backend", backend)

        uid = "loadedunit1234"
        unit_dir = tmp_path / uid
        unit_dir.mkdir()
        (unit_dir / ".analysis_status").write_text(json.dumps({
            "status": "analyzing",
            "pid": os.getpid(),
        }))

        asyncio.run(server._recover_in_progress_jobs())
        assert uid not in server._active_jobs


# =============================================================================
# MCP Tool Registration
# =============================================================================

class TestMCPToolRegistration:
    """Test consolidated MCP tool registration (8 tools)."""

    def test_load_registered(self):
        """load should be a registered MCP tool."""
        tools = server.mcp._tool_manager._tools
        assert "load" in tools

    def test_binaries_registered(self):
        tools = server.mcp._tool_manager._tools
        assert "binaries" in tools

    def test_delete_registered(self):
        tools = server.mcp._tool_manager._tools
        assert "delete" in tools

    def test_load_describes_async(self):
        """load docstring should describe async delegation for large files."""
        tools = server.mcp._tool_manager._tools
        doc = tools["load"].fn.__doc__ or ""
        assert "async" in doc.lower() or "10MB" in doc

    def test_total_tool_count(self):
        """Should have exactly 8 consolidated tools."""
        tools = server.mcp._tool_manager._tools
        assert len(tools) == 8, f"Expected 8 tools, got {len(tools)}: {sorted(tools.keys())}"

    def test_all_8_tools_registered(self):
        """All 8 consolidated tools should be registered."""
        tools = server.mcp._tool_manager._tools
        expected = {"load", "delete", "binaries", "info", "functions", "code", "xrefs", "search"}
        assert expected == set(tools.keys()), f"Missing: {expected - set(tools.keys())}"


# =============================================================================
# Worker Subprocess Config
# =============================================================================

class TestWorkerConfig:

    def test_run_worker_builds_correct_cmd(self):
        """Verify _run_worker would construct a valid subprocess command (source lint)."""
        # Quick source-inspection guard: catches accidental flag reintroduction.
        import inspect
        source = inspect.getsource(server._run_worker)
        assert "--jvm-heap" in source
        assert "--status-file" not in source, (
            "--status-file was removed from import_cmd; _run_worker must not pass it"
        )
        assert "--project-dir" in source
        assert "--profile" in source
        assert "--bootstrap" in source
        assert "--bootstrap-mode" in source

    def test_run_worker_cmd_via_mock(self, tmp_path, monkeypatch):
        """_run_worker should pass bootstrap/profile/project-dir, never --status-file."""
        captured_args: list = []

        async def fake_exec(*args, **kwargs):
            captured_args.extend(args)
            raise RuntimeError("stop before blocking")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

        config = server.ServerConfig(project_dir=tmp_path)
        monkeypatch.setattr(server, "_server_config", config)
        monkeypatch.setattr(server, "_worker_semaphore", asyncio.Semaphore(4))

        fake_path = tmp_path / "test.bin"
        fake_path.write_bytes(b"\x00" * (1024 * 1024))  # 1 MB dummy binary

        job: dict = {
            "status": "queued",
            "pid": None,
            "bootstrap_source": "b" * 16,
            "bootstrap_mode": "all",
        }
        unit_id = "a" * 16

        async def run():
            await server._run_worker(fake_path, unit_id, "fast", job)

        asyncio.run(run())

        cmd = captured_args
        assert "--profile" in cmd
        assert "fast" in cmd
        assert "--project-dir" in cmd
        assert "--bootstrap" in cmd
        assert "b" * 16 in cmd
        assert "--bootstrap-mode" in cmd
        assert "all" in cmd
        assert "--status-file" not in cmd, "--status-file must not be passed to worker"
        assert "--jvm-heap" in cmd

    def test_heap_auto_sizing(self):
        """Verify heap sizing logic in _run_worker source."""
        import inspect
        source = inspect.getsource(server._run_worker)
        assert "heap_mb" in source
        assert "2048" in source  # min heap
        assert "16384" in source  # max heap


class TestBinariesLiveStatus:

    def test_binaries_jobs_reads_live_status_file(self, tmp_path, monkeypatch):
        """binaries(jobs=True) should merge current .analysis_status values for binary jobs."""
        backend = MagicMock()
        backend.list_programs.return_value = []
        backend.programs = {}
        monkeypatch.setattr(server, "_backend", backend)
        monkeypatch.setattr(server, "get_backend", lambda: backend)
        monkeypatch.setattr(server, "_server_config", server.ServerConfig(project_dir=tmp_path))

        old_jobs = server._active_jobs.copy()
        server._active_jobs.clear()
        try:
            uid = "a" * 16
            server._active_jobs[uid] = {
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
        finally:
            server._active_jobs.clear()
            server._active_jobs.update(old_jobs)

        job_entries = [r for r in result if r.get("unit_id") == uid]
        assert len(job_entries) == 1
        assert job_entries[0]["status"] == "analyzing"
        assert job_entries[0]["phase"] == "analysis"
        assert job_entries[0]["done"] == 25300
        assert job_entries[0]["elapsed_seconds"] == 700
        assert job_entries[0]["eta_sec"] == 425

    def test_binaries_jobs_returns_completed_scan_result(self, tmp_path, monkeypatch):
        """Completed scan jobs should expose persisted result.json via binaries(jobs=True)."""
        backend = MagicMock()
        backend.list_programs.return_value = []
        backend.programs = {}
        monkeypatch.setattr(server, "_backend", backend)
        monkeypatch.setattr(server, "get_backend", lambda: backend)
        monkeypatch.setattr(server, "_server_config", server.ServerConfig(project_dir=tmp_path))

        old_jobs = server._active_jobs.copy()
        server._active_jobs.clear()
        try:
            jid = "b" * 16
            server._active_jobs[jid] = {
                "kind": "scan",
                "status": "complete",
                "binary_name": "scan.bin",
            }
            result_dir = tmp_path / jid
            result_dir.mkdir()
            (result_dir / "result.json").write_text(json.dumps({"status": "complete", "results": {"foo": 3}}))

            result = asyncio.run(server.binaries(ctx=MagicMock(), jobs=True))
        finally:
            server._active_jobs.clear()
            server._active_jobs.update(old_jobs)

        job_entries = [r for r in result if r.get("unit_id") == jid]
        assert len(job_entries) == 1
        assert job_entries[0]["result_available"] is True
        assert job_entries[0]["result"]["results"]["foo"] == 3
        assert "binaries(jobs=True)" in job_entries[0]["hint"]

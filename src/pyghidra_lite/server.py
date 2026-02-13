"""pyghidra-lite MCP server - capability-based toolset with auto-detection."""

import asyncio
import logging
import os
import shlex
import sys
import threading
import time
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import click
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_lite import __version__
import json
import signal

from pyghidra_lite.backend import (
    DEFAULT_PROJECT_DIR,
    GhidraBackend,
    compute_unit_id_streaming,
)
from pyghidra_lite.models import (
    AnalysisProfile,
    BytesResult,
    CrossRef,
    DecompiledFunction,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    StringXref,
    SymbolInfo,
)
from pyghidra_lite.tools import GhidraTools

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Thread pool for running blocking Ghidra operations
_import_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ghidra-import")


# =============================================================================
# PROGRESS TRACKING
# =============================================================================

@dataclass
class ProgressTracker:
    """Thread-safe progress tracker for long-running operations."""
    progress: int = 0
    total: int = 100
    message: str = ""
    phase: str = "starting"
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def update(self, progress: int, message: str = "", phase: str = "") -> None:
        """Update progress (called from worker thread)."""
        with self._lock:
            self.progress = progress
            if message:
                self.message = message
            if phase:
                self.phase = phase

    def get(self) -> tuple[int, int, str]:
        """Get current progress (called from async context)."""
        with self._lock:
            return self.progress, self.total, self.message or self.phase


# =============================================================================
# CAPABILITY TRACKING
# =============================================================================

@dataclass
class BinaryCapabilities:
    """Detected capabilities for a loaded binary."""
    name: str
    is_macho: bool = False
    is_elf: bool = False
    is_pe: bool = False
    has_swift: bool = False
    has_objc: bool = False
    has_hermes: bool = False
    swift_module: str | None = None


# Global state
_backend: GhidraBackend | None = None
_capabilities: dict[str, BinaryCapabilities] = {}
_backend_lock = threading.RLock()

# Async job tracking for analyze_binary
_active_jobs: dict[str, dict] = {}  # unit_id → job dict
_active_jobs_lock: asyncio.Lock | None = None  # initialized in serve
_worker_semaphore: asyncio.Semaphore | None = None  # initialized in serve, default 4


@dataclass
class ServerConfig:
    """Configuration for backend initialization and import policy."""
    project_name: str = "pyghidra_lite"
    project_dir: Path | None = None
    default_profile: AnalysisProfile = AnalysisProfile.FAST
    ghidra_dir: Path | None = None
    runtime_home: Path | None = None
    allow_any_path: bool = False
    allowed_paths: list[Path] = field(default_factory=list)
    shared: bool = False  # True for SSE (shared server), False for stdio (isolated)

    def resolved_allowed_paths(self) -> list[Path]:
        """Return de-duplicated, resolved allowlist roots."""
        roots = []
        seen = set()
        for path in self.allowed_paths:
            resolved = path.expanduser().resolve()
            if resolved not in seen:
                roots.append(resolved)
                seen.add(resolved)
        return roots


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_jvm_options(value: str) -> list[str]:
    """Best-effort split for JVM option environment variables."""
    raw = value.strip()
    if not raw:
        return []
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()


def _upsert_jvm_option(env_var: str, prefix: str, option: str) -> None:
    """Insert or replace a JVM option in an env var while preserving other flags."""
    options = _split_jvm_options(os.environ.get(env_var, ""))
    options = [existing for existing in options if not existing.startswith(prefix)]
    options.append(option)
    os.environ[env_var] = " ".join(options)


def _ensure_runtime_environment(project_dir: Path | None, runtime_home: Path | None) -> Path:
    """Ensure Ghidra runtime state is kept in a writable, process-local location."""
    base = runtime_home or ((project_dir or DEFAULT_PROJECT_DIR) / ".runtime-home")
    resolved_home = base.expanduser().resolve()
    resolved_home.mkdir(parents=True, exist_ok=True)

    config_home = resolved_home / ".config"
    cache_home = resolved_home / ".cache"
    config_home.mkdir(parents=True, exist_ok=True)
    cache_home.mkdir(parents=True, exist_ok=True)

    os.environ.setdefault("XDG_CONFIG_HOME", str(config_home))
    os.environ.setdefault("XDG_CACHE_HOME", str(cache_home))

    user_home_opt = f"-Duser.home={resolved_home}"
    for env_var in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"):
        options = _split_jvm_options(os.environ.get(env_var, ""))
        if any(opt.startswith("-Duser.home=") for opt in options):
            continue
        options.append(user_home_opt)
        os.environ[env_var] = " ".join(options)

    return resolved_home


def _load_config_from_env() -> ServerConfig:
    config = ServerConfig()
    if project_name := os.getenv("PYGHIDRA_LITE_PROJECT_NAME"):
        config.project_name = project_name
    if project_dir := os.getenv("PYGHIDRA_LITE_PROJECT_DIR"):
        config.project_dir = Path(project_dir)
    if ghidra_dir := os.getenv("GHIDRA_INSTALL_DIR"):
        config.ghidra_dir = Path(ghidra_dir)
    if runtime_home := os.getenv("PYGHIDRA_LITE_RUNTIME_HOME"):
        config.runtime_home = Path(runtime_home)
    if default_profile := os.getenv("PYGHIDRA_LITE_DEFAULT_PROFILE"):
        try:
            config.default_profile = AnalysisProfile(default_profile)
        except ValueError:
            logger.warning("Ignoring invalid PYGHIDRA_LITE_DEFAULT_PROFILE=%s", default_profile)
    if allow_any := os.getenv("PYGHIDRA_LITE_ALLOW_ANY_PATH"):
        config.allow_any_path = _parse_bool(allow_any)
    if allowed_paths := os.getenv("PYGHIDRA_LITE_ALLOWED_PATHS"):
        config.allowed_paths.extend(Path(p) for p in allowed_paths.split(os.pathsep) if p)
    return config


_server_config = _load_config_from_env()


def configure_server(
    *,
    project_name: str | None = None,
    project_dir: Path | None = None,
    default_profile: AnalysisProfile | None = None,
    ghidra_dir: Path | None = None,
    runtime_home: Path | None = None,
    allow_any_path: bool | None = None,
    allowed_paths: list[Path] | None = None,
    shared: bool | None = None,
) -> None:
    """Apply runtime configuration for backend and import policy."""
    global _server_config
    if project_name is not None:
        _server_config.project_name = project_name
    if project_dir is not None:
        _server_config.project_dir = project_dir
    if default_profile is not None:
        _server_config.default_profile = default_profile
    if ghidra_dir is not None:
        _server_config.ghidra_dir = ghidra_dir
    if runtime_home is not None:
        _server_config.runtime_home = runtime_home
    if allow_any_path is not None:
        _server_config.allow_any_path = allow_any_path
    if allowed_paths:
        _server_config.allowed_paths.extend(allowed_paths)
    if shared is not None:
        _server_config.shared = shared


def get_backend() -> GhidraBackend:
    """Get the global backend instance."""
    global _backend
    if _backend is None:
        raise RuntimeError("Backend not initialized")
    return _backend


def _require_backend():
    """Raise McpError if backend not initialized."""
    if _backend is None:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message="Backend not initialized"))


def _init_backend(eager_load: bool = False) -> GhidraBackend:
    """Initialize the backend if needed."""
    global _backend
    if _backend is None:
        config = _server_config
        resolved_runtime_home = _ensure_runtime_environment(config.project_dir, config.runtime_home)
        config.runtime_home = resolved_runtime_home
        logger.info("Using runtime home: %s", resolved_runtime_home)
        _backend = GhidraBackend(
            project_name=config.project_name,
            project_dir=config.project_dir,
            default_profile=config.default_profile,
            shared=config.shared,
            ghidra_dir=config.ghidra_dir,
        )
        _backend.start(eager_load=eager_load)
    return _backend


def _resolve_import_path(path: str) -> Path:
    """Resolve and enforce allowlist policy for imports."""
    requested = Path(path).expanduser()
    resolved = requested.resolve()
    config = _server_config
    if config.allow_any_path:
        return resolved
    allowed_roots = config.resolved_allowed_paths()
    if not allowed_roots:
        raise ValueError("No allowed paths configured")
    for root in allowed_roots:
        try:
            if resolved.is_relative_to(root):
                return resolved
        except ValueError:
            continue
    roots = ", ".join(str(root) for root in allowed_roots)
    if requested != resolved:
        raise ValueError(
            f"Path not allowed: requested={requested}, resolves_to={resolved}. "
            f"Allowed: {roots}. If this is an intentional symlink, add an allow root "
            f"for the resolved target with --allow-path."
        )
    raise ValueError(f"Path not allowed: {resolved}. Allowed: {roots}")


def _get_handle(binary: str):
    backend = get_backend()
    return backend.get_program(binary)


def _ensure_capabilities(handle) -> BinaryCapabilities:
    with _backend_lock:
        caps = _capabilities.get(handle.unit_id)
        if not caps:
            caps = detect_capabilities(handle)
            _capabilities[handle.unit_id] = caps
        return caps


def _available_tools(caps: BinaryCapabilities) -> list[str]:
    tools = [
        "list_functions",
        "get_function_info",
        "disassemble",
        "decompile",
        "search_strings",
        "search_symbols",
        "list_imports",
        "list_exports",
        "get_xrefs",
        "get_callees",
        "read_bytes",
        "read_string",
    ]

    if caps.is_elf:
        tools.extend(["elf_info", "elf_sections", "elf_symbols", "elf_got_plt"])
    if caps.is_macho:
        tools.extend(["macho_info", "macho_segments", "macho_dylibs"])
    if caps.has_swift:
        tools.extend(["swift_functions", "swift_types", "swift_decompile", "demangle"])
    if caps.has_objc:
        tools.extend(["objc_classes", "objc_methods", "objc_decompile"])
    if caps.has_hermes:
        tools.extend(["hermes_info", "hermes_components", "hermes_endpoints"])

    return tools


def _guarded_tool_call(action: str, op):
    try:
        return op()
    except McpError:
        raise
    except ValueError as exc:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(exc))) from exc
    except Exception as exc:
        logger.exception("%s failed", action)
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"{action} failed: {exc}")) from exc


def _with_handle(action: str, binary: str, op):
    with _backend_lock:
        return _guarded_tool_call(action, lambda: op(_get_handle(binary)))


async def _warn_if_limit_reached(
    ctx: Context,
    action: str,
    limit: int | None,
    count: int,
    *,
    suggest_compact: bool = False,
) -> None:
    if not limit or limit <= 0:
        return
    if count < limit:
        return
    hint = "Use pattern/limit to narrow."
    if suggest_compact:
        hint = "Use pattern/limit or compact to narrow."
    await ctx.warning(f"{action} reached limit={limit}; results may be truncated. {hint}")


def get_capabilities(binary: str) -> BinaryCapabilities:
    """Get capabilities for a binary, looked up by unit_id or name."""
    with _backend_lock:
        # Direct lookup by unit_id
        if binary in _capabilities:
            return _capabilities[binary]

        # Resolve name → handle → unit_id
        handle = _get_handle(binary)
        return _ensure_capabilities(handle)


def detect_capabilities(handle, deep: bool = False) -> BinaryCapabilities:
    """Detect binary capabilities using fast section-based heuristics.

    Args:
        handle: Program handle.
        deep: If True, do thorough detection including symbol iteration.
              Default False uses fast section name checks only.
    """
    caps = BinaryCapabilities(name=handle.name)

    # Detect format from metadata (fast - just string check)
    fmt = handle.metadata.get("Executable Format", "").lower()
    if "mach-o" in fmt or "mac os" in fmt:
        caps.is_macho = True
    elif "elf" in fmt:
        caps.is_elf = True
    elif "pe" in fmt or "portable executable" in fmt:
        caps.is_pe = True

    # Fast detection using memory block names (no symbol iteration!)
    mem = handle.program.getMemory()
    block_names_lower = " ".join(block.getName() for block in mem.getBlocks()).lower()

    # Swift: check for swift metadata sections
    if any(s in block_names_lower for s in ["swift5", "__swift", "swift_"]):
        caps.has_swift = True

    # ObjC: check for objc sections
    if any(s in block_names_lower for s in ["__objc_", "objc_class", "objc_data"]):
        caps.has_objc = True

    # Deep detection only if requested (expensive!)
    if deep:
        from pyghidra_lite.hermes import HermesTools
        try:
            hermes_tools = HermesTools(handle)
            if hermes_tools.is_hermes():
                caps.has_hermes = True
        except Exception as e:
            logger.debug(f"Hermes detection failed: {e}")

        # Get Swift module name if Swift detected
        if caps.has_swift:
            from pyghidra_lite.swift import SwiftTools
            try:
                swift_tools = SwiftTools(handle)
                info = swift_tools.get_swift_info()
                caps.swift_module = info.module_name
            except Exception as e:
                logger.debug(f"Swift info failed: {e}")

    return caps


def detect_binary_kind(path: Path, data: bytes | None = None) -> str:
    """Detect binary type from magic bytes."""
    if data is None:
        with open(path, "rb") as f:
            data = f.read(16)

    if data[:4] == b"\x7fELF":
        return "elf"
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                       b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    elif data[:4] == b"\xca\xfe\xba\xbe":
        return "macho"  # Fat binary
    elif data[:2] == b"MZ":
        return "pe"
    elif data[:4] == b"dex\n" or data[:4] == b"dey\n":
        return "dex"
    elif data[:4] == b"PK\x03\x04":
        return "archive"
    return "unknown"


def detect_container_type(path: Path) -> str | None:
    """Detect if file is a container (APK/IPA/AppImage)."""
    suffix = path.suffix.lower()
    if suffix == ".apk":
        return "apk"
    elif suffix == ".ipa":
        return "ipa"
    elif suffix == ".appimage":
        return "appimage"
    elif suffix in (".zip", ".jar"):
        return "zip"
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
            if b"AI\x02" in magic:
                return "appimage"
    except Exception:
        pass
    return None


@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[None]:
    global _backend
    with _backend_lock:
        _init_backend()

    # Start filesystem watcher for hot-loading completed analyses
    observer = None
    projects_dir = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
    projects_dir.mkdir(parents=True, exist_ok=True)
    try:
        loop = asyncio.get_event_loop()
        observer = start_project_watcher(_backend, projects_dir, loop)
        logger.info(f"Filesystem watcher started on {projects_dir}")
    except Exception as e:
        logger.warning(f"Failed to start filesystem watcher: {e}")

    # Recover any in-progress jobs from previous server run
    await _recover_in_progress_jobs()

    # Start background stale job monitor
    stale_task = asyncio.create_task(_stale_job_monitor(interval=30))

    try:
        yield
    finally:
        stale_task.cancel()
        if observer:
            observer.stop()
            observer.join(timeout=2)
        with _backend_lock:
            if _backend:
                _backend.close()
                _backend = None
            _capabilities.clear()


mcp = FastMCP("pyghidra-lite", lifespan=server_lifespan)


# =============================================================================
# ASYNC ANALYSIS HELPERS
# =============================================================================

def _read_status_file(unit_id: str) -> dict:
    """Read .analysis_status for a unit_id, returning {} on any failure."""
    status_file = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR) / unit_id / ".analysis_status"
    if not status_file.exists():
        return {}
    try:
        return json.loads(status_file.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def _write_status_file(unit_id: str, data: dict):
    """Atomic write of .analysis_status for a unit_id."""
    project_dir = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR) / unit_id
    project_dir.mkdir(parents=True, exist_ok=True)
    status_file = project_dir / ".analysis_status"
    tmp = status_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=None))
    tmp.rename(status_file)


def _format_capabilities(caps: BinaryCapabilities) -> list[str]:
    """Convert BinaryCapabilities to a flat list of strings."""
    result = []
    if caps.is_elf: result.append("elf")
    if caps.is_macho: result.append("macho")
    if caps.is_pe: result.append("pe")
    if caps.has_swift: result.append("swift")
    if caps.has_objc: result.append("objc")
    if caps.has_hermes: result.append("hermes")
    return result


_TIME_CONSTANTS = {
    "fast":    {"per_mb": 5,  "base": 5},
    "default": {"per_mb": 15, "base": 10},
    "deep":    {"per_mb": 45, "base": 15},
}


def _estimate_analysis_time(binary_size_bytes: int, profile: str) -> int:
    """Rough wall-clock estimate in seconds. Includes ~5s JVM startup."""
    mb = binary_size_bytes / (1024 * 1024)
    c = _TIME_CONSTANTS.get(profile, _TIME_CONSTANTS["default"])
    return int(max(c["base"], mb * c["per_mb"] + 5))


def _pid_alive(pid: int) -> bool:
    """Check if a process is still running.

    Returns False only if the process is confirmed dead (ProcessLookupError).
    PermissionError means the process exists but is owned by another user - treat as alive.
    """
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we lack permission - assume it's alive
        logger.debug(f"Cannot verify pid {pid} (permission denied), assuming alive")
        return True


async def _run_worker(path: Path, unit_id: str, profile: str, job: dict):
    """Acquire semaphore slot, spawn import subprocess, track completion."""
    global _worker_semaphore
    if _worker_semaphore is None:
        _worker_semaphore = asyncio.Semaphore(4)

    async with _worker_semaphore:
        job["status"] = "analyzing"

        # Auto-size JVM heap based on binary size
        binary_mb = path.stat().st_size / (1024 * 1024)
        heap_mb = max(2048, min(8192, int(binary_mb * 4)))

        cmd = [
            sys.executable, "-m", "pyghidra_lite.server",
            "import", str(path),
            "--profile", profile,
            "--status-file",
            "--project-dir", str(_server_config.project_dir or DEFAULT_PROJECT_DIR),
            "--jvm-heap", f"{heap_mb}m",
        ]

        if _server_config.ghidra_dir:
            cmd.extend(["--ghidra-dir", str(_server_config.ghidra_dir)])
        if _server_config.runtime_home:
            cmd.extend(["--runtime-home", str(_server_config.runtime_home)])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            job["pid"] = proc.pid

            _stdout, stderr_bytes = await proc.communicate()
            returncode = proc.returncode if proc.returncode is not None else -1

            if returncode == 0:
                job["status"] = "complete"
            else:
                stderr = (stderr_bytes or b"").decode(errors="replace")
                if not stderr:
                    # Fallback: worker may have recorded error in status file.
                    status_data = _read_status_file(unit_id)
                    stderr = str(status_data.get("error", "Worker exited with non-zero status"))
                job["status"] = "error"
                job["error"] = stderr[-500:]

        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)


def _hot_load_blocking(unit_id: str) -> None:
    """Load a completed project into the running backend (blocking, runs in thread pool)."""
    with _backend_lock:
        if _backend is None:
            return
        # Already loaded (race guard)
        if any(h.unit_id == unit_id for h in _backend.programs.values()):
            return

        project_dir = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR) / unit_id
        if not project_dir.exists():
            return

        try:
            project = _backend._get_or_create_project_for_binary(unit_id)
            _backend._projects[unit_id] = project

            root_folder = project.getRootFolder()
            for domain_file in root_folder.getFiles():
                if str(domain_file.getContentType()) == "Program":
                    prog_name = domain_file.getName()
                    program = project.openProgram("/", prog_name, False)
                    handle = _backend._init_program_handle(
                        program, prog_name, unit_id=unit_id
                    )
                    handle.analyzed = True
                    _backend.programs[prog_name] = handle
                    _ensure_capabilities(handle)
                    logger.info(f"Hot-loaded {prog_name} (unit_id={unit_id})")
                    break  # One program per project
        except Exception as e:
            logger.error(f"Failed to hot-load {unit_id}: {e}")


async def _hot_load(unit_id: str) -> None:
    """Async wrapper: hot-load a completed project into the backend."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(_import_executor, _hot_load_blocking, unit_id)

    # Notify MCP client that tool list may have changed
    # (new capabilities = new format-specific tools available)
    try:
        await mcp.server.send_notification("notifications/tools/list_changed", {})
    except Exception:
        pass  # Client may not support this notification


# =============================================================================
# FILESYSTEM WATCHER (Hot-loading)
# =============================================================================

class ProjectWatcher:
    """Watch projects dir for completed analyses, hot-load into backend.

    Uses watchdog's FileSystemEventHandler to detect .analysis_status writes.
    When a status file transitions to "complete", schedules a hot-load on
    the async event loop.
    """

    def __init__(self, backend, projects_dir: Path, loop: asyncio.AbstractEventLoop):
        self.backend = backend
        self.projects_dir = projects_dir
        self.loop = loop
        self._pending_hot_loads: set[str] = set()

    def on_moved(self, event):
        """Catch atomic rename: .tmp -> .analysis_status."""
        dest = Path(event.dest_path)
        if dest.name == ".analysis_status":
            self._check_and_load(dest)

    def on_modified(self, event):
        """Catch direct writes to .analysis_status."""
        path = Path(event.src_path)
        if path.name != ".analysis_status":
            return
        self._check_and_load(path)

    def _check_and_load(self, status_path: Path):
        # Validate status_path is within projects_dir before any read
        # (prevents following symlinks outside projects root).
        try:
            resolved_status = status_path.resolve()
            resolved_root = self.projects_dir.resolve()
            _ = resolved_status.relative_to(resolved_root)
        except (ValueError, FileNotFoundError, OSError):
            logger.warning(f"Status file outside projects_dir: {status_path}")
            return

        try:
            status = json.loads(resolved_status.read_text())
        except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
            logger.debug(f"Ignoring invalid status file {status_path}: {e}")
            return

        if status.get("status") != "complete":
            return

        unit_id = resolved_status.parent.name
        # Validate unit_id format (should be 16-char hex hash, or 40-char for SHA256)
        if not unit_id or not all(c in '0123456789abcdef' for c in unit_id.lower()):
            logger.warning(f"Invalid unit_id format in watcher: {unit_id}")
            return

        with _backend_lock:
            if self.backend and any(
                h.unit_id == unit_id for h in list(self.backend.programs.values())
            ):
                return  # Already loaded

        if unit_id in self._pending_hot_loads:
            return

        self._pending_hot_loads.add(unit_id)
        try:
            # Schedule callback first; create coroutine/task on event loop thread.
            self.loop.call_soon_threadsafe(self._schedule_hot_load, unit_id)
        except RuntimeError as e:
            self._pending_hot_loads.discard(unit_id)
            logger.debug(f"Failed to schedule hot-load for {unit_id}: {e}")

    def _schedule_hot_load(self, unit_id: str) -> None:
        if self.loop.is_closed():
            self._pending_hot_loads.discard(unit_id)
            return
        try:
            task = asyncio.create_task(self._async_hot_load(unit_id))
            task.add_done_callback(lambda _t: self._pending_hot_loads.discard(unit_id))
        except RuntimeError as e:
            self._pending_hot_loads.discard(unit_id)
            logger.debug(f"Failed to create hot-load task for {unit_id}: {e}")

    async def _async_hot_load(self, unit_id: str):
        try:
            await _hot_load(unit_id)
            logger.info(f"Watcher hot-loaded {unit_id}")
        except Exception as e:
            logger.error(f"Watcher failed to hot-load {unit_id}: {e}")
        finally:
            self._pending_hot_loads.discard(unit_id)


def start_project_watcher(
    backend, projects_dir: Path, loop: asyncio.AbstractEventLoop
):
    """Start a filesystem watcher on the projects directory.

    Returns the Observer instance (call .stop() on shutdown).
    """
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    handler = ProjectWatcher(backend, projects_dir, loop)

    # Wrap as a proper FileSystemEventHandler
    class _Handler(FileSystemEventHandler):
        def on_moved(self, event):
            handler.on_moved(event)
        def on_modified(self, event):
            handler.on_modified(event)

    observer = Observer()
    observer.schedule(_Handler(), str(projects_dir), recursive=True)
    observer.daemon = True
    observer.start()
    return observer


# =============================================================================
# CRASH RECOVERY & STALE JOB DETECTION (Phase 5)
# =============================================================================

async def _recover_in_progress_jobs():
    """Recover from server restart: detect running/stale workers from previous run."""
    projects_path = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
    if not projects_path.exists():
        return

    for entry in projects_path.iterdir():
        if not entry.is_dir():
            continue
        status_file = entry / ".analysis_status"
        if not status_file.exists():
            continue

        uid = entry.name
        with _backend_lock:
            if _backend and any(h.unit_id == uid for h in list(_backend.programs.values())):
                continue  # Already loaded by eager_load

        try:
            status = json.loads(status_file.read_text())
        except json.JSONDecodeError:
            continue

        if status.get("status") == "complete":
            continue  # Will be handled by eager_load or watcher

        pid = status.get("pid")
        alive = pid and _pid_alive(pid)

        if status.get("status") == "analyzing" and alive:
            # Worker still running from before restart -- track it
            _active_jobs[uid] = {
                "unit_id": uid,
                "binary_name": status.get("binary_name", uid),
                "status": "analyzing",
                "pid": pid,
                "recovered": True,
            }
            logger.info(f"Recovered in-progress job {uid} (pid={pid})")

        elif status.get("status") in ("analyzing", "queued"):
            # Worker died -- mark failed
            status["status"] = "error"
            status["error"] = f"Worker process {pid} died (server restarted)"
            _write_status_file(uid, status)
            logger.warning(f"Marked stale job {uid} as error (pid={pid})")


async def _stale_job_monitor(interval: int = 30):
    """Periodically check for crashed workers."""
    while True:
        await asyncio.sleep(interval)
        for uid, job in list(_active_jobs.items()):
            if job.get("status") != "analyzing":
                continue
            pid = job.get("pid")
            if pid and not _pid_alive(pid):
                status_data = _read_status_file(uid)
                # Check if it actually completed (status file might say "complete")
                if status_data.get("status") == "complete":
                    job["status"] = "complete"
                    continue
                logger.warning(f"Stale job {uid}: pid {pid} dead")
                _write_status_file(uid, {
                    "status": "error",
                    "error": f"Worker process {pid} died unexpectedly",
                    "phase": "unknown",
                })
                _active_jobs.pop(uid, None)


# =============================================================================
# CORE TOOLS (Always available)
# =============================================================================

def _do_import_blocking(
    p: Path,
    profile_enum: AnalysisProfile,
    analyze: bool,
    tracker: ProgressTracker,
) -> tuple:
    """Blocking import operation (runs in thread pool).

    Lock scope is minimised: we hold _backend_lock only for the fast
    import_binary() call (which mutates backend.programs), then release
    it before the potentially long-running analyzeAll() so other MCP
    tool calls aren't blocked for the entire analysis duration.
    """
    tracker.update(10, "Loading file")

    # Hold lock only for the import (mutates shared state)
    with _backend_lock:
        backend = get_backend()
        tracker.update(20, "Importing to Ghidra")
        handle = backend.import_binary(p, profile_enum, analyze=False)

    tracker.update(40, "Import complete")

    # Analysis runs outside the lock — analyzeAll() operates on a
    # per-program transaction and doesn't need the global lock.
    if analyze:
        tracker.update(50, "Analyzing")
        backend.analyze_program(handle.name, profile_enum)
        tracker.update(85, "Analysis complete")

    tracker.update(90, "Detecting capabilities")
    caps = _ensure_capabilities(handle)
    tracker.update(100, "Complete")

    return handle, caps


@mcp.tool()
async def import_binary(
    path: str,
    ctx: Context,
    profile: str = "fast",
    analyze: bool = True,
    list_tools: bool = False,
) -> dict:
    """[Deprecated: use analyze_binary for non-blocking analysis]
    Import and analyze a binary file. Blocks until analysis completes.

    For large binaries this may time out. Prefer analyze_binary() which returns
    immediately and runs analysis in an isolated subprocess.

    Args:
        path: Path to binary file.
        profile: Analysis depth - "fast" (default), "default", or "deep".
        analyze: Run analysis (set False for large binaries to avoid timeout).
        list_tools: Include available_tools list (default False, saves tokens).
    """
    try:
        p = _resolve_import_path(path)
    except ValueError as exc:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(exc))) from exc
    if not p.exists():
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Not found: {p}"))

    try:
        profile_enum = AnalysisProfile(profile)
    except ValueError as exc:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="Invalid profile. Use: fast, default, deep"
        )) from exc

    with open(p, "rb") as f:
        header = f.read(16)

    kind = detect_binary_kind(p, header)
    file_size_mb = p.stat().st_size / (1024 * 1024)

    logger.info(f"Importing {p.name} ({kind}, {file_size_mb:.1f}MB) with profile={profile_enum.value}")

    # Progress tracking
    tracker = ProgressTracker(message="Starting")
    loop = asyncio.get_event_loop()

    # Run blocking import in thread pool
    import_future = loop.run_in_executor(
        _import_executor,
        lambda: _do_import_blocking(p, profile_enum, analyze, tracker)
    )

    # Report progress: every 10% change OR every 60s
    last_reported_bucket = -1
    last_report_time = time.monotonic()

    try:
        while not import_future.done():
            now = time.monotonic()
            progress, total, message = tracker.get()
            bucket = progress // 10
            time_since_update = now - last_report_time

            # Report if 10% change OR 60s elapsed
            if bucket != last_reported_bucket or time_since_update >= 60:
                await ctx.report_progress(progress, total, message)
                last_reported_bucket = bucket
                last_report_time = now

            await asyncio.sleep(0.5)

        # Get result (raises if import failed)
        handle, caps = await asyncio.wrap_future(import_future)

        # Final progress report
        await ctx.report_progress(100, 100, "Complete")

        result = {
            "name": handle.name,
            "unit_id": handle.unit_id,
            "kind": kind,
            "capabilities": _format_capabilities(caps),
        }

        # Only include tool list if requested (saves tokens)
        if list_tools:
            result["available_tools"] = _available_tools(caps)

        return result
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Import failed: {e}")) from e


@mcp.tool()
async def analyze_binary(
    paths: list[str],
    ctx: Context,
    profile: str = "default",
) -> list[dict]:
    """Start async analysis of one or more binaries. Returns immediately with job status.

    Unlike import_binary (which blocks until complete), this spawns isolated subprocess
    workers and returns in <1 second. Poll with analysis_status() for progress.

    Args:
        paths: List of file paths to analyze.
        profile: Analysis depth - "fast", "default", or "deep".
    """
    _require_backend()
    config = _server_config

    try:
        profile_enum = AnalysisProfile(profile)
    except ValueError as exc:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Invalid profile '{profile}'. Use: fast, default, deep"
        )) from exc

    results = []
    for p in paths:
        try:
            path = _resolve_import_path(p)
        except ValueError as exc:
            results.append({"path": p, "status": "error", "error": str(exc)})
            continue

        if not path.exists():
            results.append({"path": p, "status": "error", "error": f"Not found: {path}"})
            continue

        unit_id = compute_unit_id_streaming(path)
        project_dir = Path(config.project_dir or DEFAULT_PROJECT_DIR) / unit_id

        # Case 1: Already loaded in memory
        handle = None
        with _backend_lock:
            loaded_handles = list(_backend.programs.values()) if _backend else []
        for h in loaded_handles:
            if h.unit_id == unit_id:
                handle = h
                break

        if handle:
            caps = _ensure_capabilities(handle)
            results.append({
                "unit_id": unit_id,
                "binary_name": path.name,
                "status": "ready",
                "functions": handle.program.getFunctionManager().getFunctionCount(),
                "capabilities": _format_capabilities(caps),
            })
            continue

        # Case 2: Completed on disk but not loaded
        gpr = project_dir / f"{unit_id}.gpr"
        status_file = project_dir / ".analysis_status"
        if gpr.exists() and status_file.exists():
            try:
                status = json.loads(status_file.read_text())
                if status.get("status") == "complete":
                    results.append({
                        "unit_id": unit_id,
                        "binary_name": path.name,
                        "status": "ready",
                        "functions": status.get("functions"),
                        "capabilities": status.get("capabilities", []),
                        "note": "on_disk, will load on first query",
                    })
                    continue
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        # Case 3: Already in progress
        if unit_id in _active_jobs:
            job = _active_jobs[unit_id]
            results.append({
                "unit_id": unit_id,
                "binary_name": path.name,
                "status": job.get("status", "unknown"),
                "eta_sec": job.get("eta_sec"),
            })
            continue

        # Case 4: New analysis — spawn worker subprocess
        estimated = _estimate_analysis_time(path.stat().st_size, profile)
        job = {
            "unit_id": unit_id,
            "binary_name": path.name,
            "status": "queued",
            "eta_sec": estimated,
            "profile": profile,
            "pid": None,
        }
        _active_jobs[unit_id] = job
        asyncio.create_task(_run_worker(path, unit_id, profile, job))

        results.append({
            "unit_id": unit_id,
            "binary_name": path.name,
            "status": "queued",
            "eta_sec": estimated,
        })

    return results


@mcp.tool()
async def analysis_status(
    ctx: Context,
    unit_ids: list[str] | None = None,
) -> list[dict]:
    """Check status of analysis jobs. Returns progress, phase, and completion info.

    On completion, the binary becomes available for querying via other tools.

    Args:
        unit_ids: Unit IDs to check. If omitted, returns status for all active jobs.
    """
    _require_backend()

    ids = unit_ids or list(_active_jobs.keys())
    if not ids:
        return [{"status": "no_active_jobs"}]

    # Fields the LLM agent actually needs from the status file
    _STATUS_KEYS = {"status", "phase", "progress", "functions", "capabilities",
                    "error", "binary_name", "done", "total"}

    results = []
    for uid in ids:
        # Already loaded in memory
        handle = None
        with _backend_lock:
            loaded_handles = list(_backend.programs.values()) if _backend else []
        for h in loaded_handles:
            if h.unit_id == uid:
                handle = h
                break

        if handle:
            caps = _ensure_capabilities(handle)
            results.append({
                "unit_id": uid,
                "binary_name": handle.name,
                "status": "ready",
                "functions": handle.program.getFunctionManager().getFunctionCount(),
                "capabilities": _format_capabilities(caps),
            })
            _active_jobs.pop(uid, None)
            continue

        # Read status file from disk
        raw = _read_status_file(uid)
        if not raw:
            # If worker has been queued but has not yet written status to disk,
            # fall back to in-memory job state for immediate polling feedback.
            job = _active_jobs.get(uid)
            if job:
                results.append({
                    "unit_id": uid,
                    "binary_name": job.get("binary_name", uid),
                    "status": job.get("status", "unknown"),
                    "eta_sec": job.get("eta_sec"),
                })
            else:
                results.append({"unit_id": uid, "status": "not_found"})
            continue

        # Auto hot-load on completion
        hot_loaded = False
        hot_load_error = None
        if raw.get("status") == "complete":
            try:
                await _hot_load(uid)
                hot_loaded = True
            except Exception as e:
                hot_load_error = str(e)

        # Clean up terminal jobs from active tracking
        if raw.get("status") in ("complete", "error", "cancelled"):
            _active_jobs.pop(uid, None)

        # Return only agent-relevant fields
        entry = {"unit_id": uid}
        for k in _STATUS_KEYS:
            if k in raw:
                entry[k] = raw[k]
        if hot_loaded:
            entry["hot_loaded"] = True
        if hot_load_error:
            entry["hot_load_error"] = hot_load_error
        results.append(entry)

    return results


@mcp.tool()
async def cancel_analysis(unit_id: str, ctx: Context) -> dict:
    """Kill the worker subprocess for a given analysis job.

    Args:
        unit_id: The unit_id of the analysis to cancel.
    """
    _require_backend()

    if unit_id not in _active_jobs:
        return {"unit_id": unit_id, "status": "not_found"}

    job = _active_jobs[unit_id]
    pid = job.get("pid")

    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait up to 5 seconds for graceful termination
            for _ in range(50):
                await asyncio.sleep(0.1)
                if not _pid_alive(pid):
                    break
            else:
                # Process still alive after 5s - force kill
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        except ProcessLookupError:
            pass  # Already dead

    _active_jobs.pop(unit_id, None)
    _write_status_file(unit_id, {"status": "cancelled"})
    return {"unit_id": unit_id, "status": "cancelled"}


@mcp.tool()
def list_binaries(ctx: Context, list_tools: bool = False) -> list[dict]:
    """List all binaries - ready, analyzing, queued, or on-disk from previous runs.

    Args:
        list_tools: Include available_tools list per binary (default False, saves tokens).
    """
    def op():
        backend = get_backend()
        results = []
        seen_uids = set()

        # 1. Currently loaded in memory
        for name in backend.list_programs():
            handle = backend.get_program(name)
            seen_uids.add(handle.unit_id)
            caps = _ensure_capabilities(handle)
            result = {
                "name": handle.name,
                "unit_id": handle.unit_id,
                "status": "ready",
                "profile": handle.profile.value if handle.profile else None,
                "capabilities": _format_capabilities(caps),
            }
            if list_tools:
                result["available_tools"] = _available_tools(caps)
            results.append(result)

        # 2. In-progress analyses (not yet loaded)
        for unit_id, job in _active_jobs.items():
            if unit_id not in seen_uids:
                seen_uids.add(unit_id)
                results.append({
                    "unit_id": unit_id,
                    "name": job.get("binary_name", unit_id),
                    "status": job.get("status", "unknown"),
                    "profile": job.get("profile"),
                    "eta_sec": job.get("eta_sec"),
                })

        # 3. On-disk projects not yet loaded (from previous runs, CLI imports)
        projects_path = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
        if projects_path.exists():
            for entry in projects_path.iterdir():
                uid = entry.name
                if uid in seen_uids or not entry.is_dir():
                    continue
                if not list(entry.glob("*.gpr")):
                    continue
                seen_uids.add(uid)
                status_data = _read_status_file(uid)
                results.append({
                    "unit_id": uid,
                    "name": status_data.get("binary_name", uid),
                    "status": status_data.get("status", "on_disk"),
                    "functions": status_data.get("functions"),
                    "capabilities": status_data.get("capabilities", []),
                })

        return results

    with _backend_lock:
        return _guarded_tool_call("list_binaries", op)


@mcp.tool()
async def list_functions(
    binary: str,
    ctx: Context,
    pattern: str = "",
    limit: int = 50,
    sort_by: str = "name",
    compact: bool = True,
    include_metadata: bool = False,
) -> list[FunctionInfo] | list[dict]:
    """List functions in binary.

    Args:
        binary: Binary name.
        pattern: Filter by name substring.
        limit: Max results (default 50).
        sort_by: "name", "refs_in" (importance), "refs_out" (complexity), "size".
        compact: Return only name/address (default True, saves tokens).
        include_metadata: Include refs_in/refs_out counts (slower, default False).
    """
    results = _with_handle(
        "list_functions",
        binary,
        lambda handle: GhidraTools(handle).list_functions(
            pattern=pattern, limit=limit, sort_by=sort_by,
            include_metadata=include_metadata or sort_by in ("refs_in", "refs_out"),
        ),
    )
    await _warn_if_limit_reached(
        ctx, "list_functions", limit, len(results), suggest_compact=True
    )
    if compact:
        return [{"name": f.name, "addr": f.address} for f in results]
    return results


@mcp.tool()
def decompile(
    binary: str,
    function: str,
    ctx: Context,
    include_callees: bool = True,
    include_strings: bool = True,
    include_provenance: bool = False,
) -> DecompiledFunction:
    """Decompile a function.

    Args:
        binary: Binary name.
        function: Function name or address (0x...).
        include_callees: Include list of called functions (default True).
        include_strings: Include string references (default True).
        include_provenance: Include analysis metadata (default False, saves tokens).
    """
    return _with_handle(
        "decompile",
        binary,
        lambda handle: GhidraTools(handle).decompile_function(
            function,
            include_callees=include_callees,
            include_strings=include_strings,
            include_provenance=include_provenance,
        ),
    )


@mcp.tool()
def search_strings(binary: str, query: str, ctx: Context, limit: int = 30) -> list[StringXref]:
    """Find strings and what functions reference them.

    Args:
        binary: Binary name.
        query: String pattern to search.
        limit: Max results.
    """
    return _with_handle(
        "search_strings",
        binary,
        lambda handle: GhidraTools(handle).search_strings(query, limit=limit),
    )


@mcp.tool()
def list_imports(binary: str, ctx: Context, pattern: str = "", limit: int = 50) -> list[ImportInfo]:
    """List imports with capability tags (crypto, network, file, etc).

    Args:
        binary: Binary name.
        pattern: Filter by name/library.
        limit: Max results.
    """
    return _with_handle(
        "list_imports",
        binary,
        lambda handle: GhidraTools(handle).list_imports(pattern=pattern, limit=limit),
    )


@mcp.tool()
async def list_exports(
    binary: str,
    ctx: Context,
    pattern: str = "",
    limit: int = 50,
    compact: bool = True,
) -> list[ExportInfo] | list[dict]:
    """List exported symbols.

    Args:
        binary: Binary name.
        pattern: Filter by name.
        limit: Max results (default 50).
        compact: Return only names to reduce tokens (default true).
    """
    results = _with_handle(
        "list_exports",
        binary,
        lambda handle: GhidraTools(handle).list_exports(pattern=pattern, limit=limit),
    )
    await _warn_if_limit_reached(ctx, "list_exports", limit, len(results))
    if compact:
        return [{"name": e.name} for e in results]
    return results


@mcp.tool()
def get_xrefs(binary: str, target: str, ctx: Context, limit: int = 50) -> list[CrossRef]:
    """Get cross-references TO a target (who calls/uses this).

    Args:
        binary: Binary name.
        target: Function name or address.
        limit: Max results.
    """
    return _with_handle(
        "get_xrefs",
        binary,
        lambda handle: GhidraTools(handle).get_xrefs(target, limit=limit),
    )


@mcp.tool()
def read_bytes(
    binary: str,
    address: str,
    size: int,
    ctx: Context,
    include_provenance: bool = False,
) -> BytesResult:
    """Read raw bytes at address.

    Args:
        binary: Binary name.
        address: Hex address (0x...) or symbol name.
        size: Bytes to read (1-4096).
        include_provenance: Include analysis metadata (default False).
    """
    return _with_handle(
        "read_bytes",
        binary,
        lambda handle: GhidraTools(handle).read_bytes(
            address, size, include_provenance=include_provenance
        ),
    )


@mcp.tool()
def read_string(binary: str, address: str, ctx: Context) -> str:
    """Read null-terminated string at address.

    Args:
        binary: Binary name.
        address: Hex address (0x...).
    """
    return _with_handle(
        "read_string",
        binary,
        lambda handle: GhidraTools(handle).read_string(address),
    )


@mcp.tool()
def get_callees(binary: str, function: str, ctx: Context) -> list[str]:
    """Get functions called BY this function.

    Args:
        binary: Binary name.
        function: Function name or address.
    """
    return _with_handle(
        "get_callees",
        binary,
        lambda handle: GhidraTools(handle).get_callees(function),
    )


@mcp.tool()
def batch_decompile(
    binary: str,
    functions: list[str],
    ctx: Context,
    include_callees: bool = False,
    include_strings: bool = False,
) -> list[DecompiledFunction]:
    """Decompile multiple functions in one call (reduces round trips).

    Args:
        binary: Binary name.
        functions: List of function names or addresses.
        include_callees: Include callee lists (increases response size).
        include_strings: Include string references (increases response size).

    Returns:
        List of decompiled functions. Failed functions have error in code field.
    """
    return _with_handle(
        "batch_decompile",
        binary,
        lambda handle: GhidraTools(handle).batch_decompile(
            functions,
            include_callees=include_callees,
            include_strings=include_strings,
        ),
    )


@mcp.tool()
def call_graph(
    binary: str,
    function: str,
    ctx: Context,
    depth: int = 2,
    direction: str = "both",
) -> dict:
    """Get call graph centered on a function.

    Args:
        binary: Binary name.
        function: Function name or address.
        depth: How many levels to traverse (default 2, max 5).
        direction: "callers", "callees", or "both".

    Returns:
        Dict with nodes (functions) and edges (call relationships).
    """
    if depth > 5:
        depth = 5  # Cap depth to prevent huge graphs
    return _with_handle(
        "call_graph",
        binary,
        lambda handle: GhidraTools(handle).get_call_graph(
            function, depth=depth, direction=direction
        ),
    )


@mcp.tool()
def memory_map(binary: str, ctx: Context) -> list[dict]:
    """Get memory layout with sections and permissions.

    Args:
        binary: Binary name.

    Returns:
        List of memory regions with name, address, size, and permissions.
    """
    return _with_handle(
        "memory_map",
        binary,
        lambda handle: GhidraTools(handle).get_memory_map(),
    )


@mcp.tool()
def search_symbols(binary: str, query: str, ctx: Context, limit: int = 30) -> list[SymbolInfo]:
    """Search symbols by name.

    Args:
        binary: Binary name.
        query: Name substring (case-insensitive).
        limit: Max results.
    """
    return _with_handle(
        "search_symbols",
        binary,
        lambda handle: GhidraTools(handle).search_symbols(query, limit=limit),
    )


@mcp.tool()
def get_function_info(binary: str, function: str, ctx: Context) -> dict:
    """Get detailed info about a single function.

    Args:
        binary: Binary name.
        function: Function name or address.
    """
    def op(handle):
        fm = handle.program.getFunctionManager()
        rm = handle.program.getReferenceManager()

        # Find function
        func = None
        if function.startswith("0x"):
            try:
                addr = handle.program.getAddressFactory().getAddress(function.replace("0x", ""))
                func = fm.getFunctionAt(addr)
            except Exception:
                pass

        if not func:
            for f in fm.getFunctions(True):
                if f.getName() == function or function.lower() in f.getName().lower():
                    func = f
                    break

        if not func:
            raise ValueError(f"Function not found: {function}")

        entry = func.getEntryPoint()
        body = func.getBody()

        # Get callers
        callers = []
        for ref in rm.getReferencesTo(entry):
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller and caller.getName() not in callers:
                callers.append(caller.getName())

        # Get callees
        callees = [f.getName() for f in func.getCalledFunctions(None)]

        return {
            "name": func.getName(),
            "address": str(entry),
            "size": int(body.getNumAddresses()),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "calling_convention": str(func.getCallingConventionName()),
            "stack_frame_size": (
                func.getStackFrame().getFrameSize() if func.getStackFrame() else None
            ),
            "num_params": func.getParameterCount(),
            "callers": callers[:20],
            "callees": callees[:20],
            "num_callers": len(list(rm.getReferencesTo(entry))),
            "num_callees": len(callees),
        }

    return _with_handle("get_function_info", binary, op)


@mcp.tool()
def disassemble(binary: str, function: str, ctx: Context, limit: int = 100) -> list[dict]:
    """Get assembly instructions for a function.

    Args:
        binary: Binary name.
        function: Function name or address.
        limit: Max instructions to return.
    """
    def op(handle):
        fm = handle.program.getFunctionManager()
        listing = handle.program.getListing()

        # Find function
        func = None
        if function.startswith("0x"):
            try:
                addr = handle.program.getAddressFactory().getAddress(function.replace("0x", ""))
                func = fm.getFunctionAt(addr)
            except Exception:
                pass

        if not func:
            for f in fm.getFunctions(True):
                if f.getName() == function or function.lower() in f.getName().lower():
                    func = f
                    break

        if not func:
            raise ValueError(f"Function not found: {function}")

        instructions = []
        body = func.getBody()

        for addr in body.getAddresses(True):
            instr = listing.getInstructionAt(addr)
            if instr:
                # Get operands
                operands = []
                for i in range(instr.getNumOperands()):
                    operands.append(str(instr.getDefaultOperandRepresentation(i)))

                instructions.append({
                    "addr": str(addr),
                    "mnemonic": str(instr.getMnemonicString()),
                    "operands": operands,
                    "bytes": instr.getBytes().hex() if instr.getBytes() else None,
                })

                if len(instructions) >= limit:
                    break

        return instructions

    return _with_handle("disassemble", binary, op)


# =============================================================================
# ELF TOOLS (Linux binaries)
# =============================================================================

@mcp.tool()
def elf_info(binary: str, ctx: Context) -> dict:
    """Get ELF binary structure summary.

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.elf import ElfTools

    def op(handle):
        info = ElfTools(handle).get_elf_info()
        return {
            "is_elf": info.is_elf,
            "bits": info.bits,
            "endian": info.endian,
            "machine": info.machine,
            "num_sections": info.num_sections,
            "num_symbols": info.num_symbols,
            "has_debug": info.has_debug,
            "is_stripped": info.is_stripped,
        }

    return _with_handle("elf_info", binary, op)


@mcp.tool()
def elf_sections(binary: str, ctx: Context) -> list[dict]:
    """List ELF sections (.text, .data, .bss, etc).

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.elf import ElfTools

    return _with_handle(
        "elf_sections",
        binary,
        lambda handle: [
            {
                "name": s.name,
                "type": s.type,
                "addr": hex(s.addr),
                "size": s.size,
                "flags": s.flags,
            }
            for s in ElfTools(handle).list_sections()
        ],
    )


@mcp.tool()
async def elf_symbols(
    binary: str,
    ctx: Context,
    pattern: str = "",
    limit: int = 50,
    compact: bool = True,
) -> list[dict]:
    """List ELF symbols (functions, objects).

    Args:
        binary: Binary name.
        pattern: Filter by name.
        limit: Max results (default 50).
        compact: Return only name/address to reduce tokens (default true).
    """
    from pyghidra_lite.elf import ElfTools

    symbols = _with_handle(
        "elf_symbols",
        binary,
        lambda handle: ElfTools(handle).list_symbols(pattern=pattern, limit=limit),
    )
    await _warn_if_limit_reached(ctx, "elf_symbols", limit, len(symbols), suggest_compact=True)
    if compact:
        return [{"name": s.name, "addr": hex(s.addr)} for s in symbols]
    return [
        {
            "name": s.name,
            "addr": hex(s.addr),
            "size": s.size,
            "type": s.type,
            "bind": s.bind,
        }
        for s in symbols
    ]


@mcp.tool()
def elf_got_plt(binary: str, ctx: Context) -> list[dict]:
    """Get GOT/PLT entries (dynamic linking).

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.elf import ElfTools

    return _with_handle(
        "elf_got_plt",
        binary,
        lambda handle: ElfTools(handle).get_got_plt(),
    )


# =============================================================================
# MACH-O TOOLS
# =============================================================================

@mcp.tool()
def macho_info(binary: str, ctx: Context) -> dict:
    """Get Mach-O binary structure (segments, dylibs, code signature).

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.macho import MachOTools

    def op(handle):
        info = MachOTools(handle).get_macho_info()
        return {
            "cpu_type": info.cpu_type,
            "num_segments": info.num_segments,
            "num_sections": info.num_sections,
            "num_dylibs": info.num_dylibs,
            "has_code_signature": info.has_code_signature,
            "entrypoint": info.entrypoint,
        }

    return _with_handle("macho_info", binary, op)


@mcp.tool()
def macho_segments(binary: str, ctx: Context) -> list[dict]:
    """List Mach-O segments and sections.

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.macho import MachOTools

    return _with_handle(
        "macho_segments",
        binary,
        lambda handle: [
            {
                "name": seg.name,
                "vmaddr": hex(seg.vmaddr),
                "vmsize": seg.vmsize,
                "sections": [
                    {"name": s.name, "addr": hex(s.addr), "size": s.size} for s in seg.sections
                ],
            }
            for seg in MachOTools(handle).list_segments()
        ],
    )


@mcp.tool()
def macho_dylibs(binary: str, ctx: Context) -> list[str]:
    """List linked dynamic libraries.

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.macho import MachOTools

    return _with_handle(
        "macho_dylibs",
        binary,
        lambda handle: [d.name for d in MachOTools(handle).list_dylibs()],
    )


# =============================================================================
# SWIFT TOOLS (Available when swift capability detected)
# =============================================================================

@mcp.tool()
async def swift_functions(
    binary: str,
    ctx: Context,
    pattern: str = "",
    kind: str | None = None,
    limit: int = 50,
    compact: bool = True,
) -> list[dict]:
    """List Swift functions with demangled names.

    Args:
        binary: Binary name.
        pattern: Filter by demangled name.
        kind: Filter by kind (function, initializer, getter, setter, witness).
        limit: Max results (default 50).
        compact: Return only demangled name/address to reduce tokens (default true).
    """
    from pyghidra_lite.swift import SwiftTools

    symbols = _with_handle(
        "swift_functions",
        binary,
        lambda handle: SwiftTools(handle).list_swift_functions(
            pattern=pattern, kind=kind, limit=limit
        ),
    )
    await _warn_if_limit_reached(
        ctx, "swift_functions", limit, len(symbols), suggest_compact=True
    )
    if compact:
        return [{"demangled": f.demangled, "address": f.address} for f in symbols]
    return [
        {
            "demangled": f.demangled,
            "mangled": f.mangled,
            "address": f.address,
            "kind": f.kind,
            "module": f.module,
        }
        for f in symbols
    ]


@mcp.tool()
def swift_types(binary: str, ctx: Context, limit: int = 50) -> list[dict]:
    """List Swift types from metadata.

    Args:
        binary: Binary name.
        limit: Max results.
    """
    from pyghidra_lite.swift import SwiftTools

    return _with_handle(
        "swift_types",
        binary,
        lambda handle: [
            {"name": t.name, "module": t.module, "kind": t.kind}
            for t in SwiftTools(handle).list_swift_types(limit=limit)
        ],
    )


@mcp.tool()
def swift_decompile(binary: str, function: str, ctx: Context) -> dict:
    """Decompile Swift function with demangled callees.

    Args:
        binary: Binary name.
        function: Function name (mangled or demangled) or address.
    """
    from pyghidra_lite.swift import SwiftTools

    return _with_handle(
        "swift_decompile",
        binary,
        lambda handle: SwiftTools(handle).decompile_swift(function),
    )


@mcp.tool()
def demangle(name: str, ctx: Context) -> str:
    """Demangle a Swift symbol name.

    Args:
        name: Mangled Swift symbol (e.g., _$s...).
    """
    from pyghidra_lite.swift import demangle_swift
    return demangle_swift(name)


# =============================================================================
# OBJECTIVE-C TOOLS (Available when objc capability detected)
# =============================================================================

@mcp.tool()
def objc_classes(binary: str, ctx: Context, pattern: str = "", limit: int = 50) -> list[dict]:
    """List Objective-C classes.

    Args:
        binary: Binary name.
        pattern: Filter by class name.
        limit: Max results.
    """
    from pyghidra_lite.objc import ObjCTools

    return _with_handle(
        "objc_classes",
        binary,
        lambda handle: [
            {
                "name": c.name,
                "address": c.address,
                "num_methods": len(c.methods),
            }
            for c in ObjCTools(handle).list_classes(pattern=pattern, limit=limit)
        ],
    )


@mcp.tool()
def objc_methods(
    binary: str,
    ctx: Context,
    class_name: str | None = None,
    pattern: str = "",
    limit: int = 50,
) -> list[dict]:
    """List Objective-C methods.

    Args:
        binary: Binary name.
        class_name: Filter by class.
        pattern: Filter by selector.
        limit: Max results.
    """
    from pyghidra_lite.objc import ObjCTools

    return _with_handle(
        "objc_methods",
        binary,
        lambda handle: [
            {
                "signature": m.signature,
                "class": m.class_name,
                "selector": m.selector,
                "is_class_method": m.is_class_method,
                "address": m.impl_address,
            }
            for m in ObjCTools(handle).list_methods(
                class_name=class_name, pattern=pattern, limit=limit
            )
        ],
    )


@mcp.tool()
def objc_decompile(binary: str, signature: str, ctx: Context) -> dict:
    """Decompile an Objective-C method.

    Args:
        binary: Binary name.
        signature: Method signature like "-[NSObject init]".
    """
    from pyghidra_lite.objc import ObjCTools

    return _with_handle(
        "objc_decompile",
        binary,
        lambda handle: ObjCTools(handle).decompile_method(signature),
    )


# =============================================================================
# HERMES / REACT NATIVE TOOLS
# =============================================================================

@mcp.tool()
def hermes_info(binary: str, ctx: Context) -> dict:
    """Check for Hermes bytecode (React Native).

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.hermes import HermesTools

    def op(handle):
        info = HermesTools(handle).get_hermes_info()
        return {
            "is_hermes": info.is_hermes,
            "num_strings": info.num_strings,
            "bundle_size": info.bundle_size,
        }

    return _with_handle("hermes_info", binary, op)


@mcp.tool()
def hermes_components(binary: str, ctx: Context, limit: int = 50) -> list[dict]:
    """Find React component names in bundle.

    Args:
        binary: Binary name.
        limit: Max results.
    """
    from pyghidra_lite.hermes import HermesTools

    return _with_handle(
        "hermes_components",
        binary,
        lambda handle: HermesTools(handle).find_react_components(limit=limit),
    )


@mcp.tool()
def hermes_endpoints(binary: str, ctx: Context, limit: int = 50) -> list[dict]:
    """Find API endpoints and URLs in React Native bundle.

    Args:
        binary: Binary name.
        limit: Max results.
    """
    from pyghidra_lite.hermes import HermesTools

    return _with_handle(
        "hermes_endpoints",
        binary,
        lambda handle: HermesTools(handle).extract_api_endpoints(limit=limit),
    )


# =============================================================================
# PROJECT MANAGEMENT
# =============================================================================

@mcp.tool()
def delete_binary(binary: str, ctx: Context) -> str:
    """Remove binary from project.

    Args:
        binary: Binary name.
    """
    def op():
        backend = get_backend()
        handle = backend.get_program(binary)
        if handle.unit_id in _capabilities:
            del _capabilities[handle.unit_id]
        if backend.delete_program(handle.name):
            return f"Deleted {handle.name}"
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Failed to delete {handle.name}"))

    with _backend_lock:
        return _guarded_tool_call("delete_binary", op)


@mcp.tool()
def reanalyze(binary: str, ctx: Context, profile: str = "deep", list_tools: bool = False) -> dict:
    """Re-run analysis with different profile. Re-detects capabilities.

    Args:
        binary: Binary name.
        profile: New profile - "fast", "default", or "deep".
        list_tools: Include available_tools list (default False, saves tokens).
    """
    try:
        profile_enum = AnalysisProfile(profile)
    except ValueError as exc:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Invalid profile '{profile}'. Use: fast, default, deep"
        )) from exc

    def op():
        backend = get_backend()
        handle = backend.get_program(binary)
        backend.analyze_program(handle.name, profile_enum)

        # Re-detect capabilities after deeper analysis
        caps = detect_capabilities(handle)
        _capabilities[handle.unit_id] = caps

        result = {
            "name": handle.name,
            "profile": profile,
            "capabilities": _format_capabilities(caps),
        }
        if list_tools:
            result["available_tools"] = _available_tools(caps)
        return result

    with _backend_lock:
        return _guarded_tool_call("reanalyze", op)


# =============================================================================
# CLI
# =============================================================================

class DefaultGroup(click.Group):
    """Routes unrecognized first args to the 'serve' subcommand for backward compat.

    This ensures existing MCP configs (e.g. `pyghidra-lite --allow-any-path`)
    continue to work without requiring `pyghidra-lite serve --allow-any-path`.
    """

    # Group-level flags that should NOT be routed to serve
    _group_flags = frozenset({"-v", "--version", "--help", "-h"})

    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and args[0] not in self._group_flags:
            args = ["serve"] + args
        return super().parse_args(ctx, args)


@click.group(cls=DefaultGroup)
@click.version_option(__version__, "-v", "--version")
def cli():
    """pyghidra-lite: Lightweight reverse engineering via MCP."""


@cli.command("serve")
@click.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="Transport: stdio only (sse disabled)",
)
@click.option("-p", "--port", type=int, default=8000)
@click.option("--host", type=str, default="127.0.0.1")
@click.option("--profile", type=click.Choice(["fast", "default", "deep"]), default="fast",
              help="Default analysis profile (fast recommended for MCP timeout limits)")
@click.option("--project-name", type=str, default="pyghidra_lite",
              help="Ghidra project name")
@click.option("--project-dir", type=click.Path(path_type=Path), default=None,
              help="Project directory")
@click.option("--ghidra-dir", type=click.Path(path_type=Path), default=None,
              help="Ghidra installation directory (overrides GHIDRA_INSTALL_DIR env var)")
@click.option(
    "--runtime-home",
    type=click.Path(path_type=Path),
    default=None,
    envvar="PYGHIDRA_LITE_RUNTIME_HOME",
    help="Directory used for Ghidra runtime state (JAVA user.home and XDG fallback).",
)
@click.option(
    "--allow-path",
    "allow_paths",
    type=click.Path(path_type=Path),
    multiple=True,
    help="Allow importing binaries from this path (repeatable).",
)
@click.option(
    "--allow-any-path",
    is_flag=True,
    help="Allow importing binaries from any path (unsafe).",
)
@click.option("--max-workers", type=int, default=4,
              help="Max concurrent analysis workers (default 4).")
@click.option(
    "--eager-load/--no-eager-load",
    default=False,
    help="Load all cached projects at startup (slower startup, higher memory).",
)
@click.argument("binaries", nargs=-1, type=click.Path(exists=True, path_type=Path))
def serve_cmd(
    transport: str,
    port: int,
    host: str,
    profile: str,
    project_name: str,
    project_dir: Path | None,
    ghidra_dir: Path | None,
    runtime_home: Path | None,
    allow_paths: tuple[Path, ...],
    allow_any_path: bool,
    max_workers: int,
    eager_load: bool,
    binaries: tuple[Path, ...],
):
    """Start the MCP server (default when no subcommand given)."""
    global _backend, _worker_semaphore, _active_jobs_lock

    if transport != "stdio":
        raise click.ClickException("SSE transport is disabled. Use --transport stdio.")

    _worker_semaphore = asyncio.Semaphore(max_workers)
    _active_jobs_lock = asyncio.Lock()

    logger.info(f"pyghidra-lite v{__version__} (profile={profile}, transport={transport})")

    profile_enum = AnalysisProfile(profile)
    configure_server(
        project_name=project_name,
        project_dir=project_dir,
        default_profile=profile_enum,
        ghidra_dir=ghidra_dir,
        runtime_home=runtime_home,
        allow_any_path=allow_any_path,
        allowed_paths=list(allow_paths),
        shared=True,
    )
    with _backend_lock:
        _backend = _init_backend(eager_load=eager_load)

    # Detect capabilities for all pre-loaded (eager-loaded) binaries
    for prog_name in _backend.list_programs():
        handle = _backend.get_program(prog_name)
        _ensure_capabilities(handle)
        logger.info(f"Pre-loaded {handle.name} (unit_id={handle.unit_id}, analyzed={handle.analyzed})")

    # Import binaries from command line
    for binary_path in binaries:
        try:
            handle = _backend.import_binary(binary_path, profile_enum, analyze=True)
            caps = _ensure_capabilities(handle)
            logger.info(
                "Loaded %s: swift=%s, objc=%s, hermes=%s",
                handle.name,
                caps.has_swift,
                caps.has_objc,
                caps.has_hermes,
            )
        except Exception as e:
            logger.error(f"Failed to import {binary_path}: {e}")

    logger.info(f"Ready. {len(_backend.programs)} programs loaded.")

    # mcp.run() triggers server_lifespan which starts watcher, recovery, and stale monitor
    try:
        mcp.run(transport="stdio")
    finally:
        if _backend:
            _backend.close()


@cli.command("import")
@click.argument("binaries", nargs=-1, type=click.Path(exists=True))
@click.option("--profile", default="default",
              type=click.Choice(["fast", "default", "deep"]),
              help="Analysis profile (default recommended for offline import)")
@click.option("--ghidra-dir", type=click.Path(path_type=Path), default=None,
              envvar="GHIDRA_INSTALL_DIR",
              help="Ghidra installation directory")
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=DEFAULT_PROJECT_DIR, envvar="PYGHIDRA_LITE_PROJECT_DIR",
              help="Project directory")
@click.option(
    "--runtime-home",
    type=click.Path(path_type=Path),
    default=None,
    envvar="PYGHIDRA_LITE_RUNTIME_HOME",
    help="Directory used for Ghidra runtime state (JAVA user.home and XDG fallback).",
)
@click.option("--status-file", is_flag=True,
              help="Write progress to .analysis_status (for subprocess workers)")
@click.option("--jvm-heap", default=None,
              help="JVM max heap (e.g. '4g'). Auto-sized if not set.")
def import_cmd(binaries, profile, ghidra_dir, project_dir, runtime_home, status_file, jvm_heap):
    """Import and analyze binaries offline. No MCP server started."""
    if not binaries:
        click.echo("No binaries specified.", err=True)
        raise SystemExit(1)

    resolved_runtime_home = _ensure_runtime_environment(project_dir, runtime_home)
    logger.info("Using runtime home: %s", resolved_runtime_home)

    if jvm_heap:
        _upsert_jvm_option("_JAVA_OPTIONS", "-Xmx", f"-Xmx{jvm_heap}")

    profile_enum = AnalysisProfile(profile)

    backend = GhidraBackend(
        project_dir=project_dir,
        default_profile=profile_enum,
        shared=True,
        ghidra_dir=ghidra_dir,
    )
    backend.start(eager_load=False)

    for binary_path in binaries:
        path = Path(binary_path).resolve()
        unit_id = compute_unit_id_streaming(path)
        project_dir_path = Path(project_dir) / unit_id

        listener = None
        if status_file:
            status_path = project_dir_path / ".analysis_status"
            status_path.parent.mkdir(parents=True, exist_ok=True)
            listener = AnalysisProgressListener(
                status_path, path.name, profile, path.stat().st_size
            )

        try:
            if listener:
                listener.set_phase("importing")

            handle = backend.import_binary(path, profile_enum, analyze=True)

            caps = detect_capabilities(handle)
            cap_list = []
            if caps.is_elf: cap_list.append("ELF")
            if caps.is_macho: cap_list.append("Mach-O")
            if caps.has_swift: cap_list.append("Swift")
            if caps.has_objc: cap_list.append("ObjC")
            if caps.has_hermes: cap_list.append("Hermes")

            func_count = handle.program.getFunctionManager().getFunctionCount()

            if handle.analyzed and not listener:
                # Re-opened existing project, analysis was skipped
                click.echo(f"  {path.name}: already analyzed "
                           f"(unit_id={unit_id}, {func_count} functions)")
            else:
                if listener:
                    listener.complete(func_count, cap_list)
                click.echo(f"  {path.name}: {func_count} functions, "
                           f"[{', '.join(cap_list) or 'generic'}] "
                           f"(unit_id={unit_id}, profile={profile})")

        except Exception as e:
            if listener:
                listener.error(str(e), "import")
            click.echo(f"  {path.name}: ERROR - {e}", err=True)

    backend.close()


@cli.command("list")
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=DEFAULT_PROJECT_DIR, envvar="PYGHIDRA_LITE_PROJECT_DIR",
              help="Project directory")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def list_cmd(project_dir, as_json):
    """List cached/analyzed binaries. No Ghidra needed."""
    projects_path = Path(project_dir)
    if not projects_path.exists():
        click.echo("No projects directory found.")
        return

    entries = []
    for entry in sorted(projects_path.iterdir()):
        if not entry.is_dir():
            continue
        gpr_files = list(entry.glob("*.gpr"))
        if not gpr_files:
            continue

        size = sum(f.stat().st_size for f in entry.rglob("*") if f.is_file())
        status_file = entry / ".analysis_status"

        status_data = {}
        if status_file.exists():
            try:
                status_data = json.loads(status_file.read_text())
            except json.JSONDecodeError:
                status_data = {"status": "corrupt_status"}

        info = {
            "unit_id": entry.name,
            "size_mb": round(size / 1024 / 1024, 1),
            "status": status_data.get("status", "ready"),
            "binary_name": status_data.get("binary_name", "unknown"),
            "functions": status_data.get("functions"),
            "capabilities": status_data.get("capabilities", []),
            "profile": status_data.get("profile"),
        }
        entries.append(info)

    if as_json:
        click.echo(json.dumps(entries, indent=2))
    else:
        if not entries:
            click.echo("No analyzed binaries found.")
            return
        for e in entries:
            caps = ", ".join(e["capabilities"]) if e["capabilities"] else "-"
            funcs = f"{e['functions']} funcs" if e["functions"] else ""
            click.echo(f"  {e['unit_id']}  {e['size_mb']:>6.1f}MB  "
                       f"[{e['status']}]  {e['binary_name']}  {funcs}  {caps}")


class AnalysisProgressListener:
    """Writes analysis progress to a JSON status file for subprocess worker consumption."""

    def __init__(self, status_path: Path, binary_name: str,
                 profile: str, binary_size: int):
        self.status_path = status_path
        self.binary_name = binary_name
        self.profile = profile
        self.binary_size = binary_size
        self.started = time.time()
        self._write({"status": "analyzing", "phase": "startup", "progress": 0.0})

    def set_phase(self, phase: str, progress: float | None = None):
        self._write({
            "status": "analyzing",
            "phase": phase,
            "progress": progress,
            "elapsed_seconds": int(time.time() - self.started),
        })

    def set_progress(self, current: int, total: int, phase: str | None = None):
        self._write({
            "status": "analyzing",
            "phase": phase or "analysis",
            "progress": round(current / max(total, 1), 3),
            "done": current,
            "total": total,
            "elapsed_seconds": int(time.time() - self.started),
        })

    def complete(self, functions: int, capabilities: list[str]):
        actual = int(time.time() - self.started)
        self._write({
            "status": "complete",
            "functions": functions,
            "capabilities": capabilities,
            "duration_seconds": actual,
        })
        # Self-calibration: log estimation accuracy for future tuning
        estimated = _estimate_analysis_time(self.binary_size, self.profile)
        ratio = actual / max(estimated, 1)
        logger.info(
            f"Estimation accuracy: {ratio:.2f}x "
            f"(actual={actual}s est={estimated}s "
            f"size={self.binary_size / 1024 / 1024:.1f}MB profile={self.profile})"
        )

    def error(self, error: str, phase: str):
        self._write({
            "status": "error",
            "error": str(error)[:500],
            "phase": phase,
            "duration_seconds": int(time.time() - self.started),
        })

    def _write(self, data: dict):
        from datetime import datetime, timezone
        data.update({
            "pid": os.getpid(),
            "binary_name": self.binary_name,
            "binary_size_bytes": self.binary_size,
            "profile": self.profile,
            "started_at": datetime.fromtimestamp(
                self.started, tz=timezone.utc
            ).isoformat(),
        })
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=None))
        tmp.rename(self.status_path)


def main():
    """Entry point for pyproject.toml console_scripts."""
    cli()


if __name__ == "__main__":
    main()

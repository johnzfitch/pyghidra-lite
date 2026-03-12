"""pyghidra-lite MCP server - capability-based toolset with auto-detection."""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass, field
from pathlib import Path

import re
import secrets

import click
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_lite import __version__
import json
import signal

from pyghidra_lite.backend import (
    DEFAULT_PROJECT_DIR,
    GhidraBackend,
    compute_unit_id_streaming,
    find_ghidra_install,
)
from pyghidra_lite.models import (
    AnalysisProfile,
    BytesResult,
    CrossRef,
    DecompiledFunction,
    EmbeddedRuntime,
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

# Binaries above this threshold are auto-delegated to async analysis in import_binary
_LARGE_BINARY_MB = 10

# Async job tracking for analyze_binary
_active_jobs: dict[str, dict] = {}  # unit_id → job dict
_active_jobs_lock: asyncio.Lock | None = None  # initialized in serve
_jobs_mutex = threading.Lock()  # guards _active_jobs dict mutations from sync callers
_worker_semaphore: asyncio.Semaphore | None = None  # initialized in serve, default 4

# Valid unit_id format: 16 lowercase hex chars (64-bit xxHash)
_UNIT_ID_RE = re.compile(r'^[0-9a-f]{16}$')


def _new_job_id() -> str:
    """Generate a random 16-hex scan job ID (passes _UNIT_ID_RE)."""
    return secrets.token_hex(8)


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
    autopurge_days: int | None = None  # Delete projects not opened in N days (None = off)

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
    autopurge_days: int | None = None,
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
    if autopurge_days is not None:
        _server_config.autopurge_days = autopurge_days


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


def _check_prerequisites(ghidra_dir: str | None) -> None:
    """Verify Java 21+ and Ghidra are available before starting the backend."""
    # Check Java is on PATH
    java_path = shutil.which("java")
    if not java_path:
        raise click.ClickException(
            "Java not found. Ghidra requires JDK 21+. "
            "Install: brew install openjdk@21 (macOS) / apt install openjdk-21-jdk (Ubuntu)"
        )

    # Parse java version from stderr
    try:
        result = subprocess.run(
            ["java", "-version"], capture_output=True, text=True, timeout=10
        )
        version_output = result.stderr + result.stdout
    except Exception as exc:
        raise click.ClickException(f"Failed to run 'java -version': {exc}")

    import re
    match = re.search(r'"(\d+)', version_output)
    if not match:
        raise click.ClickException(
            f"Could not parse Java version from: {version_output.strip()}"
        )
    major = int(match.group(1))
    if major < 21:
        raise click.ClickException(
            f"Java {major} found, but Ghidra requires JDK 21+. "
            "Install: brew install openjdk@21 (macOS) / apt install openjdk-21-jdk (Ubuntu)"
        )

    # Check Ghidra installation
    ghidra_path = find_ghidra_install(ghidra_dir)
    if ghidra_path is None:
        raise click.ClickException(
            "Ghidra installation not found. Set GHIDRA_INSTALL_DIR or install Ghidra to "
            "/opt/ghidra or ~/ghidra. Download from https://ghidra-sre.org"
        )

    logger.info(f"Prerequisites OK: Java {major}, Ghidra at {ghidra_path}")


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


def _iter_disk_status():
    """Yield (unit_id, status_dict) for every valid .analysis_status file on disk."""
    projects_path = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
    if not projects_path.exists():
        return
    for entry in projects_path.iterdir():
        if not entry.is_dir() or not _UNIT_ID_RE.match(entry.name):
            continue
        status_file = entry / ".analysis_status"
        if not status_file.exists():
            continue
        try:
            yield entry.name, json.loads(status_file.read_text())
        except (json.JSONDecodeError, OSError):
            continue


def _history_path() -> Path:
    return Path(_server_config.project_dir or DEFAULT_PROJECT_DIR) / "history.jsonl"


def _append_history(unit_id: str, binary_name: str) -> None:
    """Append one open event to history.jsonl (non-blocking, best-effort)."""
    from datetime import datetime, timezone
    entry = {
        "unit_id": unit_id,
        "binary_name": binary_name,
        "opened_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        p = _history_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.debug("Failed to write history: %s", e)


def _last_opened_by_unit_id() -> dict[str, str]:
    """Read history.jsonl and return {unit_id: most_recent_opened_at ISO string}."""
    result: dict[str, str] = {}
    path = _history_path()
    if not path.exists():
        return result
    try:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                uid = entry.get("unit_id", "")
                opened_at = entry.get("opened_at", "")
                # Lines are chronological; later lines overwrite earlier ones
                if uid and opened_at:
                    result[uid] = opened_at
            except json.JSONDecodeError:
                continue
    except OSError:
        pass
    return result


def _find_on_disk(binary: str) -> str | None:
    """Return unit_id for a completed on-disk project matching binary (unit_id hex or filename).

    Raises McpError for in-progress/errored unit_ids.
    For ambiguous filename matches, logs a warning and selects never-opened first,
    then most-recently-opened.
    Used by _get_handle to auto-lazy-load programs that exist on disk but aren't loaded.
    """
    projects_path = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
    if not projects_path.exists():
        return None

    # Fast path: exact unit_id match
    if _UNIT_ID_RE.match(binary):
        status_file = projects_path / binary / ".analysis_status"
        if status_file.exists():
            try:
                data = json.loads(status_file.read_text())
            except (json.JSONDecodeError, OSError):
                return None
            status = data.get("status")
            if status == "complete":
                return binary
            # Exists but not ready — give a specific error rather than "not found"
            msg = f"Unit {binary!r} found but status={status!r}"
            if status in ("analyzing", "queued"):
                msg += ". Poll with analysis_status() for progress."
            elif status == "error":
                msg += f": {data.get('error', 'unknown error')}"
            raise McpError(ErrorData(code=INVALID_PARAMS, message=msg))
        return None

    # Slow path: exact basename match against binary_name
    binary_base = Path(binary).name
    matches: list[tuple[str, dict]] = []
    for unit_id, data in _iter_disk_status():
        if data.get("status") == "complete" and data.get("binary_name", "") == binary_base:
            matches.append((unit_id, data))

    if len(matches) > 1:
        # Sort: never-opened (brand new) first, then by most recently opened per history.
        last_opened = _last_opened_by_unit_id()
        matches.sort(
            key=lambda t: (last_opened.get(t[0]) is None, last_opened.get(t[0]) or ""),
            reverse=True,
        )
        chosen = matches[0][0]
        others = [uid for uid, _ in matches[1:]]
        logger.warning(
            "Ambiguous name %r: %d projects match. Picking preferred project %r"
            " (never-opened first, then most recently opened). Others: %s",
            binary, len(matches), chosen, others,
        )
        return chosen
    return matches[0][0] if matches else None


def _get_handle(binary: str):
    backend = get_backend()
    try:
        return backend.get_program(binary)
    except ValueError:
        pass

    # Auto-lazy-load: find a completed project on disk by unit_id or filename
    # (raises McpError for in-progress/ambiguous — let that propagate)
    unit_id = _find_on_disk(binary)
    if unit_id:
        loaded = _hot_load_blocking(unit_id)  # RLock allows reentry; one-time cost per session
        # Resolve by unit_id — avoids re-triggering ambiguity on the original input string
        for handle in backend.programs.values():
            if handle.unit_id == unit_id:
                return handle
        if loaded:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Hot-loaded {unit_id!r} but program not found in backend; "
                        "internal name mismatch — try the full program name from list_binaries()",
            ))
        raise McpError(ErrorData(
            code=INTERNAL_ERROR,
            message=f"Hot-load failed for {unit_id!r}; check server logs",
        ))

    # Nothing found — list what's available
    loaded_names = list(backend.programs.keys())
    on_disk = [
        v.get("binary_name", k)
        for k, v in _iter_disk_status()
        if v.get("status") == "complete"
        and k not in {h.unit_id for h in backend.programs.values()}
    ]
    msg = f"Binary not found: {binary!r}. Loaded: {loaded_names}."
    if on_disk:
        msg += f" Available on disk (auto-loads on tool call): {on_disk}"
    raise McpError(ErrorData(code=INVALID_PARAMS, message=msg))


def _handle_by_unit_id(backend: GhidraBackend, unit_id: str):
    for handle in backend.programs.values():
        if handle.unit_id == unit_id:
            return handle
    return None


def _load_project_into_backend(
    backend: GhidraBackend,
    unit_id: str,
    *,
    update_capabilities: bool = False,
    append_history: bool = False,
):
    """Load a completed on-disk project into the provided backend."""
    handle = _handle_by_unit_id(backend, unit_id)
    if handle is not None:
        return handle

    project_dir = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR) / unit_id
    if not project_dir.exists():
        return None

    try:
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        project_str = str(project_dir.absolute())
        locator = ProjectLocator(project_str, unit_id)
        if not locator.exists():
            logger.warning("Ghidra project missing for unit_id=%s at %s", unit_id, project_dir)
            return None

        project = GhidraProject.openProject(project_str, unit_id, True)
        backend._projects[unit_id] = project

        root_folder = project.getRootFolder()
        for domain_file in root_folder.getFiles():
            if str(domain_file.getContentType()) != "Program":
                continue
            prog_name = domain_file.getName()
            program = project.openProgram("/", prog_name, False)
            handle = backend._init_program_handle(program, prog_name, unit_id=unit_id)
            handle.analyzed = True
            backend.programs[prog_name] = handle
            if update_capabilities:
                _ensure_capabilities(handle)
            if append_history:
                binary_name = _read_status_file(unit_id).get("binary_name", prog_name)
                _append_history(unit_id, binary_name)
            logger.info("Loaded %s from project cache (unit_id=%s)", prog_name, unit_id)
            return handle

        logger.warning("No Program entries found in project %s", unit_id)
        return None
    except Exception as exc:
        logger.error("Failed to load project %s into backend: %s", unit_id, exc)
        return None


def _resolve_bootstrap_handle(backend: GhidraBackend, bootstrap: str):
    """Resolve a bootstrap source by program name, binary name, or unit_id."""
    handle = _handle_by_unit_id(backend, bootstrap)
    if handle is not None:
        return handle

    try:
        return backend.get_program(bootstrap)
    except ValueError:
        pass

    unit_id = bootstrap if _UNIT_ID_RE.match(bootstrap) else _find_on_disk(bootstrap)
    if unit_id:
        handle = _load_project_into_backend(backend, unit_id)
        if handle is not None:
            return handle
        raise McpError(ErrorData(
            code=INTERNAL_ERROR,
            message=f"Bootstrap source {bootstrap!r} exists on disk but could not be loaded",
        ))

    loaded_names = list(backend.programs.keys())
    on_disk = [
        v.get("binary_name", k)
        for k, v in _iter_disk_status()
        if v.get("status") == "complete"
        and k not in {h.unit_id for h in backend.programs.values()}
    ]
    msg = f"Bootstrap source not found: {bootstrap!r}. Loaded: {loaded_names}."
    if on_disk:
        msg += f" Available on disk: {on_disk}"
    raise McpError(ErrorData(code=INVALID_PARAMS, message=msg))


def _normalize_bootstrap_source(bootstrap: str, dest_unit_id: str) -> str:
    """Resolve and validate bootstrap source, returning its canonical unit_id."""
    source_handle = _resolve_bootstrap_handle(get_backend(), bootstrap)
    if source_handle.unit_id == dest_unit_id:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="bootstrap source must differ from the destination binary",
        ))
    if not source_handle.analyzed:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Bootstrap source {bootstrap!r} is not analyzed yet",
        ))
    return source_handle.unit_id


def _apply_bootstrap_transfer(
    backend: GhidraBackend,
    source_binary: str,
    dest_handle,
) -> dict:
    """Transfer names from a bootstrap source to the destination handle."""
    source_handle = _resolve_bootstrap_handle(backend, source_binary)
    if source_handle.unit_id == dest_handle.unit_id:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="bootstrap source must differ from the destination binary",
        ))
    if not source_handle.analyzed:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Bootstrap source {source_binary!r} is not analyzed yet",
        ))
    if not dest_handle.analyzed:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="Destination binary must be analyzed before bootstrap can run",
        ))
    return backend.transfer_analysis(source_handle.name, dest_handle.name)


def _ensure_capabilities(handle) -> BinaryCapabilities:
    with _backend_lock:
        caps = _capabilities.get(handle.unit_id)
        if not caps:
            caps = detect_capabilities(handle)
            _capabilities[handle.unit_id] = caps
        return caps


def _available_tools(caps: BinaryCapabilities) -> list[str]:
    """Return the 8 consolidated tools (always available regardless of capabilities).

    Capabilities are now auto-detected by each tool; format/language-specific
    features are accessed via the `type` or `detail` parameters.
    """
    # All 8 consolidated tools are always available
    return ["load", "delete", "binaries", "info", "functions", "code", "xrefs", "search"]


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


def _rank_sources_blocking(exclude_name: str | None = None) -> list[dict]:
    """Rank loaded+analyzed binaries by transferable named function count.

    Counts functions whose names are not auto-generated (FUN_* / thunk_FUN_*),
    since those are the only names that bootstrap_from_version can transfer.
    Results are sorted descending — index 0 is the richest source.

    Lock is held only to snapshot the handles list; JVM enumeration runs unlocked.
    """
    with _backend_lock:
        backend = get_backend()
        handles = [h for h in backend.programs.values() if h.analyzed]

    results = []
    for handle in handles:
        if exclude_name and handle.name == exclude_name:
            continue
        fm = handle.program.getFunctionManager()
        total = fm.getFunctionCount()
        named = sum(
            1 for f in fm.getFunctions(True)
            if not f.getName().startswith(("FUN_", "thunk_FUN_"))
        )
        results.append({
            "name": handle.name,
            "unit_id": handle.unit_id,
            "total_functions": total,
            "named_functions": named,
            "named_pct": round(named / total * 100, 1) if total else 0.0,
        })

    results.sort(key=lambda r: r["named_functions"], reverse=True)
    return results


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
            from pyghidra_lite.lang import SwiftTools
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
        loop = asyncio.get_running_loop()
        observer = start_project_watcher(_backend, projects_dir, loop)
        logger.info(f"Filesystem watcher started on {projects_dir}")
    except Exception as e:
        logger.warning(f"Failed to start filesystem watcher: {e}")

    # Clean stale Ghidra lock files from previous sessions
    for lock in projects_dir.glob("*/*.lock"):
        lock.unlink(missing_ok=True)
    for lock in projects_dir.glob("*/*.lock~"):
        lock.unlink(missing_ok=True)

    # Recover any in-progress jobs from previous server run
    await _recover_in_progress_jobs()

    # Purge projects not opened within autopurge_days (never-opened projects are exempt)
    await _autopurge_stale_projects()

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


def _write_job_result(job_id: str, data: dict):
    """Atomic write of result.json for a scan job. Mirrors _write_status_file."""
    d = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR) / job_id
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "result.json.tmp"
    tmp.write_text(json.dumps(data))
    tmp.rename(d / "result.json")


def _get_job_result(job_id: str) -> dict:
    """Read result.json for a completed scan job.

    Internal helper used by tests. For MCP clients, job results are
    fetched via search() with the original query or binaries(jobs=True).
    """
    if not _UNIT_ID_RE.match(job_id):
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Invalid job_id: {job_id!r}"))
    result_file = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR) / job_id / "result.json"
    if not result_file.exists():
        status = _active_jobs.get(job_id, {}).get("status", "not_found")
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Job {job_id!r} result not available (status={status!r}). "
                    "Poll binaries(jobs=True) until complete.",
        ))
    try:
        return json.loads(result_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR,
                                 message=f"Failed to read result for {job_id!r}: {e}")) from e


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


def _compute_job_eta_sec(job: dict, status_data: dict) -> int | None:
    """Return a live ETA based on current status data when available."""
    status = status_data.get("status") or job.get("status")
    if status == "complete":
        return 0

    estimated_total = job.get("eta_sec")
    if estimated_total is None:
        return None

    elapsed = status_data.get("elapsed_seconds")
    if not isinstance(elapsed, (int, float)):
        elapsed = status_data.get("duration_seconds")
    if not isinstance(elapsed, (int, float)):
        return estimated_total

    progress = status_data.get("progress")
    if isinstance(progress, (int, float)) and 0 < progress < 1:
        return max(0, int(round(elapsed * ((1 - progress) / progress))))

    return max(0, int(round(estimated_total - elapsed)))


def _merge_live_job_entry(unit_id: str, job: dict, *, include_jobs_meta: bool) -> dict:
    """Build a binaries() entry from in-memory job data plus live status file fields."""
    entry = {
        "unit_id": unit_id,
        "name": job.get("binary_name", unit_id),
        "status": job.get("status", "unknown"),
        "profile": job.get("profile"),
    }
    if job.get("bootstrap"):
        entry["bootstrap"] = job.get("bootstrap")

    if not include_jobs_meta:
        return entry

    status_data = _read_status_file(unit_id) if job.get("kind") != "scan" else {}
    for key in (
        "status",
        "phase",
        "done",
        "total",
        "progress",
        "elapsed_seconds",
        "duration_seconds",
        "functions",
        "capabilities",
        "error",
        "started_at",
        "binary_size_bytes",
        "binary_path",
        "bootstrap",
    ):
        if key in status_data:
            entry[key] = status_data[key]

    eta_sec = _compute_job_eta_sec(job, status_data)
    if eta_sec is not None:
        entry["eta_sec"] = eta_sec

    if job.get("kind") == "scan" and job.get("status") == "complete":
        entry["hint"] = f"Call get_job_result('{unit_id}') for results"

    return entry


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

        # Auto-size JVM heap based on binary size.
        # Set -Xms = -Xmx to avoid GC resizing overhead on startup.
        binary_mb = path.stat().st_size / (1024 * 1024)
        heap_mb = max(2048, min(16384, int(binary_mb * 4)))

        cmd = [
            sys.executable, "-m", "pyghidra_lite.server",
            "import", str(path),
            "--profile", profile,
            "--project-dir", str(_server_config.project_dir or DEFAULT_PROJECT_DIR),
            "--jvm-heap", f"{heap_mb}m",
        ]
        if job.get("bootstrap"):
            cmd.extend(["--bootstrap", str(job["bootstrap"])])

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
                if not stderr.strip():
                    # Fallback: worker may have recorded error in status file.
                    status_data = _read_status_file(unit_id)
                    stderr = str(status_data.get("error", "Worker exited with non-zero status"))
                job["status"] = "error"
                job["error"] = stderr[-500:]

        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)

        # Deferred pop: keep terminal status available for 5 min so callers can poll.
        asyncio.get_running_loop().call_later(300, _active_jobs.pop, unit_id, None)


async def _run_scan_task(job_id: str, job: dict, fn):
    """Run a blocking scan function in the thread pool; write result.json on completion.

    Used by batch_search_strings(background=True) and extract_bunfs().
    On completion, job status transitions to "complete" and result is persisted to disk.
    The model should poll analysis_status(unit_ids=[job_id]) then call get_job_result(job_id).
    """
    loop = asyncio.get_running_loop()
    job["status"] = "running"
    try:
        result = await loop.run_in_executor(_import_executor, fn)
        _write_job_result(job_id, {"status": "complete", **result})
        job["status"] = "complete"
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)[:500]
        _write_job_result(job_id, {"status": "error", "error": str(e)[:500]})
    # Keep terminal state for 5 min so callers can poll after the task finishes.
    loop.call_later(300, _active_jobs.pop, job_id, None)


def _hot_load_blocking(unit_id: str) -> bool:
    """Load a completed project into the running backend (blocking, runs in thread pool).

    Returns True if the program is now in backend.programs (loaded here or already loaded),
    False if it could not be loaded.
    """
    with _backend_lock:
        if _backend is None:
            return False
        handle = _load_project_into_backend(
            _backend,
            unit_id,
            update_capabilities=True,
            append_history=True,
        )
        return handle is not None


async def _hot_load(unit_id: str) -> None:
    """Async wrapper: hot-load a completed project into the backend."""
    loop = asyncio.get_running_loop()
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
            continue  # Loaded lazily on first tool call via _get_handle/_find_on_disk

        pid = status.get("pid")
        alive = pid and _pid_alive(pid)

        if status.get("status") == "analyzing" and alive:
            # Worker still running from before restart -- track it
            entry = {
                "unit_id": uid,
                "binary_name": status.get("binary_name", uid),
                "status": "analyzing",
                "pid": pid,
                "recovered": True,
            }
            async with (_active_jobs_lock or nullcontext()):
                _active_jobs[uid] = entry
            logger.info(f"Recovered in-progress job {uid} (pid={pid})")

        elif status.get("status") in ("analyzing", "queued"):
            # Worker died -- mark failed
            status["status"] = "error"
            status["error"] = f"Worker process {pid} died (server restarted)"
            _write_status_file(uid, status)
            logger.warning(f"Marked stale job {uid} as error (pid={pid})")


async def _autopurge_stale_projects() -> None:
    """Delete on-disk projects whose last open was more than autopurge_days days ago.

    Brand-new analyses (never opened, no history entry) are always skipped — they
    may be freshly analyzed and waiting for an agent to start working on them.
    """
    days = _server_config.autopurge_days
    if not days or days <= 0:
        return

    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.isoformat()

    last_opened = _last_opened_by_unit_id()
    project_base = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)

    purged = []
    for uid, data in _iter_disk_status():
        if data.get("status") != "complete":
            continue
        last_open = last_opened.get(uid)
        if last_open is None:
            continue  # Never opened — brand new, skip
        if last_open < cutoff_str:  # ISO UTC strings compare lexicographically
            try:
                with _backend_lock:
                    active_ids = set(get_backend()._projects.keys()) if _backend else set()
                if uid in active_ids:
                    continue  # in-use — skip purge
                shutil.rmtree(project_base / uid)
                purged.append((uid, data.get("binary_name", uid)))
                logger.info("Autopurged %s (%s), last opened %s", data.get("binary_name", uid), uid, last_open)
            except OSError as e:
                logger.warning("Failed to autopurge %s: %s", uid, e)

    if purged:
        logger.info("Autopurge complete: removed %d project(s)", len(purged))


async def _stale_job_monitor(interval: int = 30):
    """Periodically check for crashed workers."""
    while True:
        await asyncio.sleep(interval)
        async with (_active_jobs_lock or nullcontext()):
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
                    with _jobs_mutex:
                        _active_jobs.pop(uid, None)


# =============================================================================
# CORE TOOLS (Always available)
# =============================================================================

def _do_import_blocking(
    p: Path,
    profile_enum: AnalysisProfile,
    analyze: bool,
    tracker: ProgressTracker,
    fresh: bool = False,
    bootstrap: str | None = None,
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
        handle = backend.import_binary(p, profile_enum, analyze=False, fresh=fresh)

    tracker.update(40, "Import complete")

    # Analysis runs outside the lock — analyzeAll() operates on a
    # per-program transaction and doesn't need the global lock.
    # Skip if program was already analyzed (preexisting on disk or in memory).
    if analyze and not handle.analyzed:
        tracker.update(50, "Analyzing")
        backend.analyze_program(handle.name, profile_enum)
        tracker.update(85, "Analysis complete")

    bootstrap_stats = None
    if bootstrap:
        tracker.update(88, "Applying bootstrap")
        with _backend_lock:
            bootstrap_stats = _apply_bootstrap_transfer(get_backend(), bootstrap, handle)

    tracker.update(90, "Detecting capabilities")
    caps = _ensure_capabilities(handle)
    tracker.update(100, "Complete")

    return handle, caps, bootstrap_stats


# =============================================================================
# CONSOLIDATED TOOLS (8 tools replacing 58)
# =============================================================================

@mcp.tool()
async def load(
    path: str,
    ctx: Context,
    profile: str = "fast",
    analyze: bool = True,
    fresh: bool = False,
    bootstrap: str | None = None,
) -> dict:
    """Import and analyze a binary file.

    For binaries under 10MB, blocks until analysis completes.
    For binaries 10MB+, runs async - poll list(jobs=True) for progress.

    Args:
        path: Path to binary file.
        profile: Analysis depth - "fast" (default), "default", or "deep".
        analyze: Run analysis (False = import only, faster).
        fresh: Discard cached analysis and re-import from scratch.
        bootstrap: Name of analyzed binary to transfer names from (version tracking).
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
    unit_id = compute_unit_id_streaming(p)
    bootstrap_source = None

    if bootstrap:
        _require_backend()
        with _backend_lock:
            bootstrap_source = _normalize_bootstrap_source(bootstrap, unit_id)

    # Auto-delegate large binaries to async analysis to avoid MCP timeouts.
    if analyze and file_size_mb >= _LARGE_BINARY_MB:
        _require_backend()

        # fresh=True: purge everything before any caching checks so the
        # subsequent import and worker spawn always start from a clean slate.
        if fresh:
            with _backend_lock:
                if _backend:
                    _backend._purge_binary(unit_id)
            project_dir_fresh = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
            proj_path = project_dir_fresh / unit_id
            if proj_path.exists():
                shutil.rmtree(proj_path, ignore_errors=True)
            async with (_active_jobs_lock or nullcontext()):
                _kill_job(unit_id)
            logger.info("fresh=True: purged all cached state for unit_id=%s", unit_id)

        # Already loaded in memory?
        if not fresh:
            with _backend_lock:
                loaded_handles = list(_backend.programs.values()) if _backend else []
            for h in loaded_handles:
                if h.unit_id == unit_id and h.analyzed:
                    caps = _ensure_capabilities(h)
                    result = {
                        "unit_id": unit_id,
                        "binary_name": p.name,
                        "kind": kind,
                        "status": "ready",
                        "functions": h.program.getFunctionManager().getFunctionCount(),
                        "capabilities": _format_capabilities(caps),
                    }
                    if bootstrap_source:
                        with _backend_lock:
                            result["bootstrap"] = _apply_bootstrap_transfer(
                                get_backend(), bootstrap_source, h
                            )
                    return result

        # Check disk: already analyzed by a previous import run? (outside lock)
        project_dir = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
        gpr = project_dir / unit_id / f"{unit_id}.gpr"
        status_file = project_dir / unit_id / ".analysis_status"
        if not fresh and gpr.exists() and status_file.exists():
            try:
                status_data = json.loads(status_file.read_text())
                if status_data.get("status") == "complete":
                    # Hot-load into memory so it's immediately available
                    hot_load_error = None
                    try:
                        await _hot_load(unit_id)
                    except Exception as e:
                        hot_load_error = str(e)
                    # Verify program actually loaded (hot-load can silently fail)
                    hot_loaded = False
                    with _backend_lock:
                        if _backend:
                            hot_loaded = any(
                                h.unit_id == unit_id for h in _backend.programs.values()
                            )
                    result = {
                        "unit_id": unit_id,
                        "binary_name": p.name,
                        "kind": kind,
                        "status": "ready" if hot_loaded else "load_failed",
                        "functions": status_data.get("functions"),
                        "capabilities": status_data.get("capabilities", []),
                    }
                    if hot_loaded:
                        result["hot_loaded"] = True
                    if hot_load_error:
                        result["hot_load_error"] = hot_load_error
                    elif not hot_loaded:
                        result["hot_load_error"] = "Program not found in backend after load"
                    if hot_loaded and bootstrap_source:
                        with _backend_lock:
                            dest_handle = _handle_by_unit_id(get_backend(), unit_id)
                            if dest_handle is not None:
                                result["bootstrap"] = _apply_bootstrap_transfer(
                                    get_backend(), bootstrap_source, dest_handle
                                )
                    return result
            except (json.JSONDecodeError, OSError):
                pass

        async with (_active_jobs_lock or nullcontext()):
            # Already in progress? (skip check when fresh — we just cleared the job)
            if not fresh and unit_id in _active_jobs:
                job = _active_jobs[unit_id]
                if job.get("status") not in ("complete", "error"):
                    if bootstrap_source and job.get("bootstrap") != bootstrap_source:
                        raise McpError(ErrorData(
                            code=INVALID_PARAMS,
                            message=(
                                f"Analysis already in progress for {p.name!r} without the "
                                "requested bootstrap source. Wait for completion or retry "
                                "with fresh=True."
                            ),
                        ))
                    entry = _merge_live_job_entry(unit_id, job, include_jobs_meta=True)
                    entry["binary_name"] = p.name
                    entry["message"] = (
                        f"Analysis in progress ({file_size_mb:.0f}MB). "
                        f"Poll with analysis_status(unit_ids=['{unit_id}'])"
                    )
                    return entry
                # Terminal state stale entry: fall through and re-queue.

            # Spawn async worker subprocess.
            estimated = _estimate_analysis_time(p.stat().st_size, profile)
            job: dict = {
                "unit_id": unit_id,
                "binary_name": p.name,
                "status": "queued",
                "eta_sec": estimated,
                "profile": profile,
                "pid": None,
                "bootstrap": bootstrap_source,
            }
            with _jobs_mutex:
                _active_jobs[unit_id] = job
            asyncio.create_task(_run_worker(p, unit_id, profile, job))
            result = {
                "unit_id": unit_id,
                "binary_name": p.name,
                "kind": kind,
                "status": "queued",
                "eta_sec": estimated,
                "message": (
                    f"Binary is {file_size_mb:.0f}MB; analysis runs in background. "
                    f"Poll with analysis_status(unit_ids=['{unit_id}'])"
                ),
            }
            if bootstrap_source:
                result["bootstrap"] = bootstrap_source
            return result

    logger.info(f"Importing {p.name} ({kind}, {file_size_mb:.1f}MB) with profile={profile_enum.value}")

    # Progress tracking
    tracker = ProgressTracker(message="Starting")
    loop = asyncio.get_running_loop()

    # Run blocking import in thread pool
    import_future = loop.run_in_executor(
        _import_executor,
        lambda: _do_import_blocking(
            p,
            profile_enum,
            analyze,
            tracker,
            fresh=fresh,
            bootstrap=bootstrap_source,
        )
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
        handle, caps, bootstrap_stats = await asyncio.wrap_future(import_future)

        # Final progress report
        await ctx.report_progress(100, 100, "Complete")

        result = {
            "name": handle.name,
            "binary_name": p.name,
            "unit_id": handle.unit_id,
            "kind": kind,
            "capabilities": _format_capabilities(caps),
            "status": "ready",
        }
        if bootstrap_stats:
            result["bootstrap"] = bootstrap_stats
        if handle.was_preexisting:
            result["note"] = "already_analyzed"

        return result
    except McpError:
        raise
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Import failed: {e}")) from e


@mcp.tool()
async def delete(name: str, ctx: Context) -> dict:
    """Remove a binary, cancel any running analysis, and delete on-disk project.

    Args:
        name: Binary name or unit_id.
    """
    def op():
        backend = get_backend()
        project_base = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)

        # Search loaded binaries without triggering auto-load
        handle = None
        exact = [h for h in backend.programs.values() if name in (h.name, h.unit_id)]
        partial = [h for h in backend.programs.values() if name in h.name] if not exact else []
        matches = exact or partial
        if len(matches) > 1:
            candidates = [f"{h.name} ({h.unit_id})" for h in matches]
            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Ambiguous match for {name!r}: {candidates}. Use exact name or unit_id.",
            ))
        handle = matches[0] if matches else None

        if handle is not None:
            unit_id = handle.unit_id
            _capabilities.pop(unit_id, None)
            deleted = backend.delete_program(handle.name)
            if not deleted:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Failed to delete {handle.name!r} from Ghidra project",
                ))
            _kill_job(unit_id)
            shutil.rmtree(project_base / unit_id, ignore_errors=True)
            return {"deleted": handle.name, "unit_id": unit_id}

        # Disk-only (errored, incomplete, never loaded)
        unit_id = name
        if not _UNIT_ID_RE.match(name):
            binary_base = Path(name).name
            candidates = [
                uid for uid, data in _iter_disk_status()
                if data.get("binary_name", "") == binary_base
            ]
            if not candidates:
                raise McpError(ErrorData(
                    code=INVALID_PARAMS,
                    message=f"Not found: {name!r}. Use unit_id from list().",
                ))
            if len(candidates) > 1:
                raise McpError(ErrorData(
                    code=INVALID_PARAMS,
                    message=f"Ambiguous name {name!r} matches {candidates}. Use unit_id.",
                ))
            unit_id = candidates[0]

        project_dir = project_base / unit_id
        if not project_dir.exists():
            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Project not found: {unit_id!r}",
            ))

        binary_name = _read_status_file(unit_id).get("binary_name", unit_id)
        _kill_job(unit_id)
        shutil.rmtree(project_dir)
        return {"deleted": binary_name, "unit_id": unit_id}

    with _backend_lock:
        return _guarded_tool_call("delete", op)


@mcp.tool()
async def binaries(
    ctx: Context,
    jobs: bool = False,
    rank_sources: bool = False,
) -> "list[dict]":
    """List all binaries - loaded, analyzing, queued, or on-disk.

    Args:
        jobs: Include active job status and results.
        rank_sources: Rank binaries by transferable named functions (for bootstrap).
    """
    if rank_sources:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _import_executor,
            lambda: _rank_sources_blocking(exclude_name=None),
        )

    def op():
        backend = get_backend()
        results = []
        seen_uids = set()
        with _jobs_mutex:
            active_jobs_snapshot = list(_active_jobs.items())

        # Currently loaded in memory
        for prog_name in backend.list_programs():
            handle = backend.get_program(prog_name)
            seen_uids.add(handle.unit_id)
            caps = _ensure_capabilities(handle)
            results.append({
                "name": handle.name,
                "unit_id": handle.unit_id,
                "status": "ready",
                "profile": handle.profile.value if handle.profile else None,
                "capabilities": _format_capabilities(caps),
            })

        # In-progress analyses
        for unit_id, job in active_jobs_snapshot:
            if unit_id not in seen_uids:
                seen_uids.add(unit_id)
                results.append(_merge_live_job_entry(unit_id, job, include_jobs_meta=jobs))

        # On-disk projects not yet loaded
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
                disk_entry = {
                    "unit_id": uid,
                    "name": status_data.get("binary_name", uid),
                    "status": status_data.get("status", "on_disk"),
                    "functions": status_data.get("functions"),
                    "capabilities": status_data.get("capabilities", []),
                }
                if jobs:
                    for key in (
                        "phase",
                        "done",
                        "total",
                        "progress",
                        "elapsed_seconds",
                        "duration_seconds",
                        "error",
                        "started_at",
                        "binary_size_bytes",
                        "binary_path",
                        "bootstrap",
                        "profile",
                    ):
                        if key in status_data:
                            disk_entry[key] = status_data[key]
                results.append(disk_entry)

        return results

    with _backend_lock:
        return _guarded_tool_call("list", op)


@mcp.tool()
def info(
    binary: str,
    ctx: Context,
    detail: str = "summary",
) -> dict:
    """Get binary overview with auto-detected format and language info.

    Args:
        binary: Binary name or unit_id.
        detail: Level of detail:
            - "summary" (default): basic info + capabilities
            - "full": triage with top functions, imports, strings
            - "format": raw format headers (ELF/Mach-O specific)
            - "sections": memory/section layout
            - "entropy": per-section entropy analysis
    """
    def op(handle):
        caps = _ensure_capabilities(handle)
        metadata = handle.metadata
        fm = handle.program.getFunctionManager()
        st = handle.program.getSymbolTable()

        # Base info (always included)
        addr_size = metadata.get("Address Size", "")
        bits = 64 if "64" in addr_size else (32 if "32" in addr_size else None)

        base = {
            "name": handle.name,
            "unit_id": handle.unit_id,
            "format": metadata.get("Executable Format", "unknown"),
            "arch": metadata.get("Processor", "unknown"),
            "bits": bits,
            "endian": metadata.get("Endian", "").lower() or None,
            "num_functions": fm.getFunctionCount(),
            "num_symbols": st.getNumSymbols(),
            "capabilities": _format_capabilities(caps),
        }

        if detail == "summary":
            return base

        tools = GhidraTools(handle)

        if detail == "entropy":
            try:
                entropy_data = tools.entropy_map()
                base["entropy"] = entropy_data
                base["high_entropy_sections"] = [
                    s for s in entropy_data if s.get("entropy", 0) > 7.0
                ]
            except Exception as e:
                base["entropy_error"] = str(e)
            return base

        if detail == "sections":
            mem = handle.program.getMemory()
            sections = []
            for block in mem.getBlocks():
                perms = ""
                if block.isRead(): perms += "r"
                if block.isWrite(): perms += "w"
                if block.isExecute(): perms += "x"
                sections.append({
                    "name": block.getName(),
                    "addr": hex(int(block.getStart().getOffset())),
                    "size": int(block.getSize()),
                    "permissions": perms or "---",
                })
            base["sections"] = sections
            return base

        if detail == "format":
            if caps.is_elf:
                from pyghidra_lite.formats import ElfTools
                elf_info = ElfTools(handle).get_elf_info()
                base["elf"] = {
                    "bits": elf_info.bits,
                    "endian": elf_info.endian,
                    "machine": elf_info.machine,
                    "num_sections": elf_info.num_sections,
                    "num_symbols": elf_info.num_symbols,
                    "has_debug": elf_info.has_debug,
                    "is_stripped": elf_info.is_stripped,
                }
            elif caps.is_macho:
                from pyghidra_lite.formats import MachOTools
                macho_info = MachOTools(handle).get_macho_info()
                base["macho"] = {
                    "cpu_type": macho_info.cpu_type,
                    "num_segments": macho_info.num_segments,
                    "num_sections": macho_info.num_sections,
                    "num_dylibs": macho_info.num_dylibs,
                    "has_code_signature": macho_info.has_code_signature,
                    "entrypoint": macho_info.entrypoint,
                }
            return base

        # detail == "full" - triage mode
        limit = 15

        # Top functions by refs_in
        funcs = tools.list_functions(limit=limit * 2, sort_by="refs_in", include_metadata=True)
        base["top_functions"] = [
            {"name": f.name, "address": f.address, "refs_in": f.refs_in}
            for f in funcs[:limit]
        ]

        # Imports (suspicious first)
        imports = tools.list_imports(limit=limit * 3)
        suspicious = [i for i in imports if i.tags]
        normal = [i for i in imports if not i.tags]
        base["top_imports"] = [
            {"name": i.name, "tags": i.tags or []}
            for i in (suspicious + normal)[:limit]
        ]

        # Notable strings
        strings = tools.search_strings("", limit=limit * 3)
        base["notable_strings"] = [
            {"value": s.value, "type": s.looks_like, "address": s.address}
            for s in strings
            if s.looks_like in ("url", "key", "path", "error")
        ][:limit]

        # Embedded runtimes
        try:
            rt_info = tools.detect_embedded_runtime(compact=True)
            if rt_info.get("runtimes"):
                base["runtimes"] = rt_info["runtimes"]
                base["strategy"] = rt_info.get("strategy")
        except Exception:
            pass

        # Language-specific info
        if caps.has_swift:
            from pyghidra_lite.lang import SwiftTools
            try:
                swift_info = SwiftTools(handle).get_swift_info()
                base["swift"] = {
                    "module_name": swift_info.module_name,
                    "num_swift_functions": swift_info.num_swift_functions,
                }
            except Exception:
                pass

        if caps.has_objc:
            from pyghidra_lite.lang import ObjCTools
            try:
                objc_info = ObjCTools(handle).get_objc_info()
                base["objc"] = {
                    "num_classes": objc_info.num_classes,
                    "num_selectors": objc_info.num_selectors,
                    "has_arc": objc_info.has_arc,
                }
            except Exception:
                pass

        return base

    return _with_handle("info", binary, op)


@mcp.tool()
async def functions(
    binary: str,
    ctx: Context,
    query: str = "",
    type: str = "all",
    limit: int = 50,
    demangle: str = "",
) -> list[dict]:
    """List or search functions by type.

    Args:
        binary: Binary name or unit_id.
        query: Filter by name substring (searches demangled names for Swift/ObjC).
        type: Function type filter:
            - "all" (default): all functions
            - "swift": Swift functions only (demangled)
            - "objc": Objective-C methods only
            - "imports": imported symbols
            - "exports": exported symbols
            - "types": Swift types (metadata)
            - "got": GOT/PLT entries (ELF)
            - "dylibs": linked dynamic libraries (Mach-O)
        limit: Max results (default 50).
        demangle: If provided, demangle this single Swift symbol name.
    """
    # Single symbol demangle shortcut
    if demangle:
        from pyghidra_lite.lang import demangle_swift
        return [{"mangled": demangle, "demangled": demangle_swift(demangle)}]

    def op(handle):
        tools = GhidraTools(handle)
        caps = _ensure_capabilities(handle)

        if type == "swift":
            if not caps.has_swift:
                return [{"error": "Binary has no Swift code"}]
            from pyghidra_lite.lang import SwiftTools
            swift_tools = SwiftTools(handle)
            results = swift_tools.list_swift_functions(pattern=query, limit=limit)
            return [
                {"demangled": f.demangled, "address": f.address, "kind": f.kind}
                for f in results
            ]

        if type == "objc":
            if not caps.has_objc:
                return [{"error": "Binary has no Objective-C code"}]
            from pyghidra_lite.lang import ObjCTools
            objc_tools = ObjCTools(handle)
            methods = objc_tools.list_methods(pattern=query, limit=limit)
            return [
                {"signature": m.signature, "class": m.class_name, "address": m.impl_address}
                for m in methods
            ]

        if type == "imports":
            imports = tools.list_imports(pattern=query, limit=limit)
            return [
                {"name": i.name, "library": i.library, "tags": i.tags or []}
                for i in imports
            ]

        if type == "exports":
            exports = tools.list_exports(pattern=query, limit=limit)
            return [{"name": e.name, "address": e.address} for e in exports]

        if type == "types":
            if not caps.has_swift:
                return [{"error": "Binary has no Swift code"}]
            from pyghidra_lite.lang import SwiftTools
            swift_tools = SwiftTools(handle)
            types = swift_tools.list_swift_types(limit=limit)
            return [
                {"name": t.name, "module": t.module, "kind": t.kind}
                for t in types
            ]

        if type == "got":
            if not caps.is_elf:
                return [{"error": "GOT/PLT only available for ELF binaries"}]
            from pyghidra_lite.formats import ElfTools
            return ElfTools(handle).get_got_plt()

        if type == "dylibs":
            if not caps.is_macho:
                return [{"error": "dylibs only available for Mach-O binaries"}]
            from pyghidra_lite.formats import MachOTools
            return [{"name": d.name} for d in MachOTools(handle).list_dylibs()]

        # Default: all functions
        funcs = tools.list_functions(pattern=query, limit=limit)
        return [{"name": f.name, "addr": f.address} for f in funcs]

    results = _with_handle("functions", binary, op)
    await _warn_if_limit_reached(ctx, "functions", limit, len(results))
    return results


@mcp.tool()
def code(
    binary: str,
    target: str | list[str],
    ctx: Context,
    what: str = "decompile",
    cfg: bool = False,
) -> dict | list[dict]:
    """Decompile or disassemble function(s).

    Args:
        binary: Binary name or unit_id.
        target: Function name/address, or list of function names for batch.
        what: Output type:
            - "decompile" (default): C pseudocode
            - "asm": assembly instructions
            - "bytes": raw bytes at address (requires address and size in target)
            - "string": null-terminated string at address
        cfg: Include control flow graph (blocks and edges).
    """
    def op(handle):
        tools = GhidraTools(handle)

        # Handle batch decompile
        if isinstance(target, list):
            results = tools.batch_decompile(
                target, include_callees=True, include_strings=True
            )
            return [
                {
                    "name": r.name,
                    "address": r.address,
                    "code": r.code,
                    "callees": r.callees,
                    "strings": r.strings_used,
                }
                for r in results
            ]

        # Single target
        if what == "asm":
            fm = handle.program.getFunctionManager()
            listing = handle.program.getListing()

            func = None
            if target.startswith("0x"):
                try:
                    addr = handle.program.getAddressFactory().getAddress(target.replace("0x", ""))
                    func = fm.getFunctionAt(addr)
                except Exception:
                    pass

            if not func:
                for f in fm.getFunctions(True):
                    if f.getName() == target or target.lower() in f.getName().lower():
                        func = f
                        break

            if not func:
                raise ValueError(f"Function not found: {target}")

            instructions = []
            body = func.getBody()
            limit = 100

            for addr in body.getAddresses(True):
                instr = listing.getInstructionAt(addr)
                if instr:
                    operands = [str(instr.getDefaultOperandRepresentation(i))
                                for i in range(instr.getNumOperands())]
                    instructions.append({
                        "addr": str(addr),
                        "mnemonic": str(instr.getMnemonicString()),
                        "operands": operands,
                    })
                    if len(instructions) >= limit:
                        break

            return {"function": func.getName(), "instructions": instructions}

        if what == "bytes":
            # target format: "addr,size" or just address
            parts = target.split(",")
            addr = parts[0].strip()
            size = int(parts[1].strip()) if len(parts) > 1 else 16
            result = tools.read_bytes(addr, size)
            return {"address": result.address, "hex": result.hex, "ascii": result.ascii}

        if what == "string":
            return {"address": target, "value": tools.read_string(target)}

        # Default: decompile
        dec = tools.decompile_function(
            target, include_callees=True, include_strings=True
        )

        result = {
            "name": dec.name,
            "address": dec.address,
            "signature": dec.signature,
            "code": dec.code,
            "callees": dec.callees,
            "strings": dec.strings_used,
        }

        if cfg:
            cfg_data = tools.get_cfg(target)
            result["cfg"] = cfg_data
            result["num_blocks"] = len(cfg_data)

        # Get callers for context
        callers = tools.get_xrefs(target, limit=10)
        result["callers"] = [
            {"name": r.from_func, "address": r.from_addr}
            for r in callers if r.type == "call"
        ]

        return result

    return _with_handle("code", binary, op)


@mcp.tool()
def xrefs(
    binary: str,
    target: str | list[str],
    ctx: Context,
    direction: str = "to",
    depth: int = 1,
    diff: bool = False,
) -> dict:
    """Get cross-references, call graph, or symbol diff.

    Args:
        binary: Binary name or unit_id.
        target: Function/symbol name or address, or list for batch, or binary name for diff.
        direction: Reference direction:
            - "to" (default): who calls/uses this target
            - "from": what this target calls/uses
        depth: Call graph depth (default 1, max 5). Use depth>1 for full call graph.
        diff: If True, compare symbols between binary and target (another binary name).
    """
    def op():
        backend = get_backend()

        # Symbol diff mode
        if diff:
            import heapq
            handle_a = backend.get_program(binary)
            handle_b = backend.get_program(target if isinstance(target, str) else target[0])

            def _get_symbols(handle) -> set[str]:
                st = handle.program.getSymbolTable()
                return {sym.getName() for sym in st.getAllSymbols(True)}

            syms_a = _get_symbols(handle_a)
            syms_b = _get_symbols(handle_b)

            return {
                "binary_a": handle_a.name,
                "binary_b": handle_b.name,
                "added": heapq.nsmallest(100, syms_b - syms_a),
                "removed": heapq.nsmallest(100, syms_a - syms_b),
                "num_added": len(syms_b - syms_a),
                "num_removed": len(syms_a - syms_b),
                "num_common": len(syms_a & syms_b),
            }

        handle = backend.get_program(binary)
        tools = GhidraTools(handle)

        # Batch xrefs
        if isinstance(target, list):
            if len(target) > 20:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Max 20 targets per call"))
            result = {}
            for t in target:
                try:
                    refs = tools.get_xrefs(t, limit=20)
                    result[t] = [
                        {"from_func": r.from_func, "from_addr": r.from_addr, "type": r.type}
                        for r in refs
                    ]
                except Exception:
                    result[t] = []
            return {"xrefs": result}

        # Call graph (depth > 1)
        if depth > 1:
            depth = min(depth, 5)
            graph_direction = "both" if direction == "to" else direction
            if direction == "from":
                graph_direction = "callees"
            elif direction == "to":
                graph_direction = "callers"
            else:
                graph_direction = "both"
            return tools.get_call_graph(target, depth=depth, direction=graph_direction)

        # Simple xrefs
        if direction == "from":
            callees = tools.get_callees(target)
            return {"function": target, "callees": callees}

        refs = tools.get_xrefs(target, limit=50)
        return {
            "target": target,
            "references": [
                {"from_func": r.from_func, "from_addr": r.from_addr, "type": r.type}
                for r in refs
            ],
        }

    with _backend_lock:
        return _guarded_tool_call("xrefs", op)


@mcp.tool()
async def search(
    binary: str,
    query: str | list[str],
    ctx: Context,
    type: str = "strings",
    mode: str = "indexed",
    limit: int = 30,
    bg: bool = False,
) -> dict:
    """Search for strings, bytes, symbols, or all.

    Args:
        binary: Binary name or unit_id.
        query: Search pattern, or list for batch search.
        type: What to search:
            - "strings" (default): string references
            - "symbols": symbol names
            - "bytes": hex byte pattern (e.g., "cafebabe")
            - "all": functions, symbols, and strings simultaneously
            - "blob": extract strings from raw memory region (query="offset,size")
            - "extract": extract bunfs filesystem (Bun binaries only)
        mode: Search mode for strings:
            - "indexed" (default): Ghidra's defined strings (fast)
            - "deep": raw memory scan (finds strings Ghidra missed)
        limit: Max results per query (default 30).
        bg: Run in background (returns job_id to poll).
    """
    handle = _get_handle(binary)
    tools = GhidraTools(handle)

    # Batch search
    if isinstance(query, list):
        if bg:
            job_id = _new_job_id()
            job: dict = {"kind": "scan", "label": "batch_search",
                         "binary": binary, "status": "queued", "job_id": job_id}
            with _jobs_mutex:
                _active_jobs[job_id] = job

            fn = lambda: {"results": tools.batch_search_strings(
                query, mode=mode, limit_per_query=limit,
            )}
            asyncio.create_task(_run_scan_task(job_id, job, fn))
            return {
                "job_id": job_id,
                "status": "queued",
                "hint": f"Poll: list(jobs=True). On complete: get results via list().",
            }

        results = tools.batch_search_strings(query, mode=mode, limit_per_query=limit)
        return {"queries": query, "results": results}

    # Single query searches
    if type == "extract":
        # BunFS extraction - always background
        status = _read_status_file(handle.unit_id)
        binary_path_str = status.get("binary_path", handle.name)
        stem = Path(binary_path_str).stem
        out = Path(binary_path_str).parent / f"{stem}_bunfs_extracted"

        job_id = _new_job_id()
        job = {"kind": "scan", "label": "extract_bunfs",
               "binary": binary, "status": "queued", "job_id": job_id}
        with _jobs_mutex:
            _active_jobs[job_id] = job

        asyncio.create_task(_run_scan_task(job_id, job, lambda: _extract_bunfs_blocking(handle, out)))
        return {
            "job_id": job_id,
            "status": "queued",
            "hint": f"Poll: list(jobs=True). On complete: get results via list().",
        }

    if type == "blob":
        parts = query.split(",")
        offset = parts[0].strip()
        size = int(parts[1].strip()) if len(parts) > 1 else 1024
        results = tools.extract_strings_from_blob(offset, size, limit=limit)
        return {"offset": offset, "size": size, "strings": results}

    if type == "bytes":
        results = tools.find_bytes(query, limit=limit)
        return {"pattern": query, "matches": results}

    if type == "symbols":
        results = tools.search_symbols(query, limit=limit)
        return {
            "query": query,
            "symbols": [
                {"name": s.name, "address": s.address, "type": s.type}
                for s in results
            ],
        }

    if type == "all":
        return {
            "query": query,
            "functions": [
                {"name": f.name, "address": f.address}
                for f in tools.list_functions(pattern=query, limit=limit)
            ],
            "symbols": [
                {"name": s.name, "address": s.address, "type": s.type}
                for s in tools.search_symbols(query, limit=limit)
            ],
            "strings": [
                {"value": s.value, "address": s.address}
                for s in tools.search_strings(query, limit=limit)
            ],
        }

    # Default: strings
    if mode == "deep":
        results = tools.search_strings_deep(query, limit=limit)
        return {"query": query, "mode": "deep", "strings": results}

    results = tools.search_strings(query, limit=limit)
    return {
        "query": query,
        "strings": [
            {"value": s.value, "address": s.address, "refs": s.refs}
            for s in results
        ],
    }


# =============================================================================
# LEGACY TOOL ALIASES (hidden from model, route to consolidated tools)
# =============================================================================

# The old tool names are no longer registered as @mcp.tool() but can still
# be called via the alias routing in consolidated.py. When list_tools is
# called, only the 8 consolidated tools are returned.


# =============================================================================
# REMOVED: Old tool registrations
# =============================================================================
# The following tools have been consolidated:
# - import_binary, analyze_binary, reanalyze -> load
# - delete_binary, cancel_analysis -> delete
# - list_binaries, analysis_status, get_job_result -> list
# - binary_info, triage_binary, elf_info, macho_info, swift_info, objc_info,
#   hermes_info, detect_embedded_runtime, entropy_map, memory_map,
#   elf_sections, macho_segments -> info
# - list_functions, swift_functions, objc_methods, objc_classes, get_function_info,
#   list_imports, list_exports, elf_symbols, elf_got_plt, macho_dylibs,
#   swift_types, demangle -> functions
# - decompile, swift_decompile, objc_decompile, decompile_with_cfg,
#   function_context, batch_decompile, disassemble, read_bytes, read_string -> code
# - get_xrefs, get_callees, batch_xrefs, call_graph, diff_symbols -> xrefs
# - search_strings, search_strings_deep, batch_search_strings, search_symbols,
#   search_all, find_bytes, extract_strings_from_blob, extract_bunfs,
#   hermes_endpoints, hermes_components -> search


# =============================================================================
# PROJECT MANAGEMENT HELPERS (kept for delete tool)
# =============================================================================

def _kill_job(unit_id: str) -> None:
    """Kill any active worker for unit_id and remove it from _active_jobs."""
    with _jobs_mutex:
        job = _active_jobs.pop(unit_id, None)
    if job:
        pid = job.get("pid")
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


# Keep _extract_bunfs_blocking for search(type="extract")
def _extract_bunfs_blocking(handle, out: Path) -> dict:
    """Extract the bunfs filesystem from a Bun binary into readable JS files."""
    rt_info = GhidraTools(handle).detect_embedded_runtime(compact=False)
    bun_rt = next((r for r in rt_info.get("runtimes", []) if r["type"] == "bunfs"), None)
    if not bun_rt:
        raise ValueError("No bunfs payload detected.")

    status = _read_status_file(handle.unit_id)
    binary_path_str = status.get("binary_path")
    if not binary_path_str:
        raise ValueError("binary_path not recorded in status file.")
    binary_path = Path(binary_path_str)
    if not binary_path.exists():
        raise FileNotFoundError(f"Original binary not found at: {binary_path}")

    out.mkdir(parents=True, exist_ok=True)
    strategy_used = None

    bun_exe = shutil.which("bun")
    if bun_exe:
        try:
            result = subprocess.run(
                [bun_exe, "x", "bun-extract-bundled", str(binary_path), str(out)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                strategy_used = "bun-extract-bundled"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    if strategy_used is None:
        raise RuntimeError("bunfs extraction failed. Install bun and retry.")

    files = list(out.rglob("*"))
    js_files = [f for f in files if f.suffix in (".js", ".ts", ".json")]
    return {
        "output_dir": str(out),
        "files_extracted": len([f for f in files if f.is_file()]),
        "js_files": len(js_files),
        "strategy_used": strategy_used,
    }


# =============================================================================
# CLI
# =============================================================================

class DefaultGroup(click.Group):
    """Routes unrecognized first args to the 'serve' subcommand for backward compat."""

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
@click.option(
    "--autopurge-days", type=int, default=None,
    help="Delete projects not opened in this many days at startup. "
         "Brand-new analyses (never opened) are always exempt.",
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
    autopurge_days: int | None,
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
        autopurge_days=autopurge_days,
    )
    _check_prerequisites(ghidra_dir)
    with _backend_lock:
        _backend = _init_backend(eager_load=eager_load)

    # Detect capabilities for all pre-loaded binaries
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
@click.option("--jvm-heap", default=None,
              help="JVM max heap (e.g. '4g'). Auto-sized if not set.")
@click.option("--bootstrap", default=None,
              help="Name or unit_id of analyzed binary to transfer names from.")
def import_cmd(binaries, profile, ghidra_dir, project_dir, runtime_home, jvm_heap, bootstrap):
    """Import and analyze binaries offline. No MCP server started."""
    if not binaries:
        click.echo("No binaries specified.", err=True)
        raise SystemExit(1)

    resolved_runtime_home = _ensure_runtime_environment(project_dir, runtime_home)
    logger.info("Using runtime home: %s", resolved_runtime_home)

    if jvm_heap:
        _upsert_jvm_option("_JAVA_OPTIONS", "-Xmx", f"-Xmx{jvm_heap}")
        _upsert_jvm_option("_JAVA_OPTIONS", "-Xms", f"-Xms{jvm_heap}")

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

        status_path = project_dir_path / ".analysis_status"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        listener = AnalysisProgressListener(
            status_path, path.name, profile, path.stat().st_size,
            binary_path=str(path),
        )

        try:
            current_phase = "import"
            listener.set_phase("importing")

            def _on_progress(func_count: int) -> None:
                listener.set_progress(func_count, 0, "analyzing")

            handle = backend.import_binary(
                path, profile_enum, analyze=True, on_progress=_on_progress
            )

            bootstrap_stats = None
            if bootstrap:
                current_phase = "bootstrap"
                bootstrap_stats = _apply_bootstrap_transfer(backend, bootstrap, handle)

            caps = detect_capabilities(handle)
            cap_list = _format_capabilities(caps)

            func_count = handle.program.getFunctionManager().getFunctionCount()
            if not handle.was_preexisting:
                listener.complete(func_count, cap_list, bootstrap=bootstrap_stats)

            if handle.was_preexisting:
                click.echo(f"  {path.name}: already analyzed "
                           f"(unit_id={unit_id}, {func_count} functions)")
            else:
                message = (f"  {path.name}: {func_count} functions, "
                           f"[{', '.join(cap_list) or 'generic'}] "
                           f"(unit_id={unit_id}, profile={profile})")
                if bootstrap_stats:
                    message += f", bootstrap transferred={bootstrap_stats['transferred']}"
                click.echo(message)

        except Exception as e:
            listener.error(str(e), current_phase)
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
                 profile: str, binary_size: int, binary_path: str | None = None):
        self.status_path = status_path
        self.binary_name = binary_name
        self.binary_path = binary_path
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
        data: dict = {
            "status": "analyzing",
            "phase": phase or "analysis",
            "done": current,
            "total": total,
            "elapsed_seconds": int(time.time() - self.started),
        }
        if total > 0:
            data["progress"] = round(current / total, 3)
        self._write(data)

    def complete(self, functions: int, capabilities: list[str], bootstrap: dict | None = None):
        actual = int(time.time() - self.started)
        data = {
            "status": "complete",
            "functions": functions,
            "capabilities": capabilities,
            "duration_seconds": actual,
        }
        if bootstrap:
            data["bootstrap"] = bootstrap
        self._write(data)
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
        if self.binary_path:
            data["binary_path"] = self.binary_path
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=None))
        tmp.rename(self.status_path)


def main():
    """Entry point for pyproject.toml console_scripts."""
    cli()


if __name__ == "__main__":
    main()


# =============================================================================
# OLD TOOLS REMOVED - DO NOT ADD BELOW THIS LINE
# =============================================================================
# All 58 original tools have been consolidated into 8 tools above:
#   load, delete, list, info, functions, code, xrefs, search
#
# Old tool names are mapped via TOOL_ALIASES in consolidated.py for
# backwards compatibility with programmatic callers.

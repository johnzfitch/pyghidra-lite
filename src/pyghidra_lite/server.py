"""pyghidra-lite MCP server - capability-based toolset with auto-detection."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
import weakref
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, nullcontext, suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Annotated, Literal

import re
import secrets

import click
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, Field
from mcp.shared.exceptions import McpError
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    ClientCapabilities,
    ElicitationCapability,
    ErrorData,
    ToolAnnotations,
)
from mcp.server.transport_security import TransportSecuritySettings

from pyghidra_lite import __version__
import json
import signal

from pyghidra_lite.backend import (
    DEFAULT_PROJECT_DIR,
    GhidraBackend,
    compute_unit_id_streaming,
    find_ghidra_install,
    make_analysis_id,
    parse_analysis_id,
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
_last_access: dict[str, float] = {}  # analysis_id -> time.monotonic()
_evicted_ids: set[str] = set()  # analysis_ids evicted from memory (still on disk)

# Cache of computed unit_ids keyed by (resolved path, mtime_ns, size) so that
# re-loading an already-analyzed binary doesn't re-stream the whole file just
# to recompute its content hash. Bounded to avoid unbounded growth.
_unit_id_cache: dict[tuple[str, int, int], str] = {}
_unit_id_cache_lock = threading.Lock()
_UNIT_ID_CACHE_MAX = 256

# Binaries above this threshold are auto-delegated to async analysis in load()
_LARGE_BINARY_MB = 10

# Async job tracking for analyze_binary
_active_jobs: dict[str, dict] = {}  # unit_id -> job dict
_active_jobs_lock: asyncio.Lock | None = None  # initialized in serve
_jobs_mutex = threading.Lock()  # guards _active_jobs dict mutations from sync callers
_worker_semaphore: asyncio.Semaphore | None = None  # initialized in serve, default 4

# Valid unit_id format: 16 lowercase hex chars (64-bit xxHash)
# \Z (not $): Python's `$` also matches before a trailing newline, so a `$`
# anchor would accept "abcdef0123456789\n" as a valid id (log-injection / odd
# filenames). \Z requires the match to reach the very end of the string.
_UNIT_ID_RE = re.compile(r'^[0-9a-f]{16}\Z')
_BOOTSTRAP_MODES = {"named", "all"}
_BOOTSTRAP_AUTO_PREFIX = "BTFN"
_INFO_DETAILS = ("summary", "full", "format", "sections", "entropy")
_FUNCTION_TYPES = ("all", "swift", "objc", "imports", "exports", "types", "got", "dylibs")
_CODE_WHATS = ("decompile", "asm", "bytes", "string")
_XREF_DIRECTIONS = ("to", "from")
_SEARCH_TYPES = ("strings", "symbols", "bytes", "all", "blob", "extract")
_SEARCH_MODES = ("indexed", "deep")
_ANNOTATE_ACTIONS = ("rename", "comment", "prototype")
_MAX_BATCH_XREF_TARGETS = 20
_MAX_BATCH_SEARCH_QUERIES = 20
_MAX_QUEUED_JOBS = 32

def _validate_project_id(project_id: str) -> None:
    """Raise ValueError if project_id doesn't match expected formats.

    Valid formats: 16-char hex (unit_id) or 16-char hex + profile suffix (analysis_id).
    """
    if _UNIT_ID_RE.match(project_id):
        return
    if parse_analysis_id(project_id) is not None:
        return
    raise ValueError(f"Invalid project_id: {project_id!r}")


def _safe_project_path(project_base: Path, project_id: str) -> Path:
    """Return project_base / project_id after validating format and containment."""
    _validate_project_id(project_id)
    result = (project_base / project_id).resolve()
    if not result.is_relative_to(project_base.resolve()):
        raise ValueError(f"Path escapes project directory: {project_id!r}")
    return result


NonEmptyStr = Annotated[str, Field(min_length=1)]
LoadProfileArg = Literal["fast", "default", "deep"]
BootstrapModeArg = Literal["named", "all"]
InfoDetailArg = Literal["summary", "full", "format", "sections", "entropy"]
FunctionsTypeArg = Literal["all", "swift", "objc", "imports", "exports", "types", "got", "dylibs"]
CodeWhatArg = Literal["decompile", "asm", "bytes", "string"]
XrefsDirectionArg = Literal["to", "from"]
AnnotateActionArg = Literal["rename", "comment", "prototype"]
SearchTypeArg = Literal["strings", "symbols", "bytes", "all", "blob", "extract"]
SearchModeArg = Literal["indexed", "deep"]
CodeTargetArg = NonEmptyStr | Annotated[list[NonEmptyStr], Field(min_length=1)]
XrefsTargetArg = NonEmptyStr | Annotated[list[NonEmptyStr], Field(
    min_length=1,
    max_length=_MAX_BATCH_XREF_TARGETS,
)]
SearchQueryArg = str | Annotated[list[str], Field(
    min_length=1,
    max_length=_MAX_BATCH_SEARCH_QUERIES,
)]


def _new_job_id() -> str:
    """Generate a random 16-hex scan job ID (passes _UNIT_ID_RE)."""
    return secrets.token_hex(8)


# Non-terminal job statuses that count against the queue cap.
_ACTIVE_JOB_STATES = ("queued", "analyzing", "running")


def _reject_if_jobs_full() -> None:
    """Raise if too many jobs are already in flight.

    Background search/extract jobs previously had no cap (only analysis jobs in
    load() did), so a client could spawn unbounded scans. Mirror the load()
    guard so all background work shares one ceiling.
    """
    with _jobs_mutex:
        active = sum(
            1 for j in _active_jobs.values()
            if j.get("status") in _ACTIVE_JOB_STATES
        )
    if active >= _MAX_QUEUED_JOBS:
        raise ValueError(
            f"Job queue full ({active} active). "
            "Wait for current jobs to complete or cancel with delete()."
        )


@dataclass(frozen=True)
class ServerConfig:
    """Immutable configuration for backend initialization and import policy.

    Frozen by design: a security setting (restrict_paths, shared, runtime_home,
    ...) must not be mutable while the server is running. The only legitimate way
    to produce one is to build it once at startup (see configure_server); there
    is no field setter, so the MITM/tamper surface -- widening restrict_paths,
    flipping shared, nulling runtime_home mid-session -- simply does not exist.
    """
    project_name: str = "pyghidra_lite"
    project_dir: Path | None = None
    default_profile: AnalysisProfile = AnalysisProfile.FAST
    ghidra_dir: Path | None = None
    runtime_home: Path | None = None
    restrict_paths: tuple[Path, ...] = ()
    shared: bool = False  # True for SSE (shared server), False for stdio (isolated)
    autopurge_days: int | None = None  # Delete projects not opened in N days (None = off)
    evict_after_minutes: int = 30  # Unload idle binaries from memory after N minutes (0 = off)
    min_loaded: int = 2  # Always keep at least N most-recently-used binaries in memory
    allow_write: bool = False  # Opt-in write tools (annotate). Off by default: read-only.

    def __post_init__(self) -> None:
        # Accept any iterable (e.g. a list from a CLI/test call) but store an
        # immutable tuple, so callers cannot append to restrict_paths after the
        # fact. object.__setattr__ is the frozen-dataclass normalization idiom.
        object.__setattr__(self, "restrict_paths", tuple(self.restrict_paths))

    def resolved_restrict_paths(self) -> list[Path]:
        """Return de-duplicated, resolved restrict roots (empty = unrestricted)."""
        roots = []
        seen = set()
        for path in self.restrict_paths:
            resolved = path.expanduser().resolve()
            if resolved not in seen:
                roots.append(resolved)
                seen.add(resolved)
        return roots


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _rmtree_warn(func, path, exc_info):
    """onerror handler for shutil.rmtree that logs instead of silencing."""
    logger.warning("rmtree failed on %s: %s", path, exc_info[1])


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
    """Build the boot-time config from the allowlisted set of env vars."""
    kwargs: dict = {}
    if project_name := os.getenv("PYGHIDRA_LITE_PROJECT_NAME"):
        kwargs["project_name"] = project_name
    if project_dir := os.getenv("PYGHIDRA_LITE_PROJECT_DIR"):
        kwargs["project_dir"] = Path(project_dir)
    if ghidra_dir := os.getenv("GHIDRA_INSTALL_DIR"):
        kwargs["ghidra_dir"] = Path(ghidra_dir)
    if runtime_home := os.getenv("PYGHIDRA_LITE_RUNTIME_HOME"):
        kwargs["runtime_home"] = Path(runtime_home)
    if default_profile := os.getenv("PYGHIDRA_LITE_DEFAULT_PROFILE"):
        try:
            kwargs["default_profile"] = AnalysisProfile(default_profile)
        except ValueError:
            logger.warning("Ignoring invalid PYGHIDRA_LITE_DEFAULT_PROFILE=%s", default_profile)
    if restrict_paths := os.getenv("PYGHIDRA_LITE_RESTRICT_PATHS"):
        kwargs["restrict_paths"] = tuple(Path(p) for p in restrict_paths.split(os.pathsep) if p)
    if "PYGHIDRA_LITE_ALLOW_WRITE" in os.environ:
        kwargs["allow_write"] = _parse_bool(os.getenv("PYGHIDRA_LITE_ALLOW_WRITE"))
    return ServerConfig(**kwargs)


_server_config = _load_config_from_env()
_config_live = False  # flips True once, at the serve boundary (go_live)


class ConfigLockedError(RuntimeError):
    """Raised when something tries to change config after the server is serving."""


def get_config() -> ServerConfig:
    """The single read path for the active (immutable) configuration."""
    return _server_config


def go_live() -> None:
    """Lock configuration for the lifetime of the serving process.

    Idempotent. Called once at the serve boundary, after all startup config is
    applied. After this, configure_server raises: the only way to change a
    setting is to stop the process and re-run the CLI. This is the allowlist
    rule -- changes are permitted only while not live, none after.
    """
    global _config_live
    _config_live = True


def is_config_live() -> bool:
    return _config_live


def configure_server(
    *,
    project_name: str | None = None,
    project_dir: Path | None = None,
    default_profile: AnalysisProfile | None = None,
    ghidra_dir: Path | None = None,
    runtime_home: Path | None = None,
    restrict_paths: list[Path] | None = None,
    shared: bool | None = None,
    autopurge_days: int | None = None,
    evict_after_minutes: int | None = None,
    min_loaded: int | None = None,
    allow_write: bool | None = None,
) -> None:
    """Build and install a fresh immutable config (the only writer).

    Permitted only before go_live(); raises ConfigLockedError afterwards. Each
    call constructs a brand-new frozen ServerConfig (dataclasses.replace) rather
    than mutating the live one, so there is no in-place write surface. restrict_paths
    is additive, preserving the prior accumulate-on-each-call behavior.
    """
    global _server_config
    if _config_live:
        raise ConfigLockedError(
            "Server configuration is locked while serving; stop the process and "
            "re-run the CLI to change settings."
        )
    cur = _server_config
    merged_restrict = cur.restrict_paths + tuple(restrict_paths) if restrict_paths else cur.restrict_paths
    _server_config = replace(
        cur,
        project_name=cur.project_name if project_name is None else project_name,
        project_dir=cur.project_dir if project_dir is None else project_dir,
        default_profile=cur.default_profile if default_profile is None else default_profile,
        ghidra_dir=cur.ghidra_dir if ghidra_dir is None else ghidra_dir,
        runtime_home=cur.runtime_home if runtime_home is None else runtime_home,
        restrict_paths=merged_restrict,
        shared=cur.shared if shared is None else shared,
        autopurge_days=cur.autopurge_days if autopurge_days is None else autopurge_days,
        evict_after_minutes=cur.evict_after_minutes if evict_after_minutes is None else evict_after_minutes,
        min_loaded=cur.min_loaded if min_loaded is None else min_loaded,
        allow_write=cur.allow_write if allow_write is None else allow_write,
    )


def get_backend() -> GhidraBackend:
    """Get the global backend instance."""
    global _backend
    if _backend is None:
        raise RuntimeError("Backend not initialized")
    return _backend


def _require_backend():
    """Raise when the backend has not been initialized yet."""
    if _backend is None:
        raise RuntimeError("Backend not initialized")


def _validate_choice(name: str, value: str, allowed: tuple[str, ...]) -> str:
    """Validate an enum-like string argument for direct Python callers."""
    if value not in allowed:
        raise ValueError(f"Invalid {name}. Use: {', '.join(allowed)}")
    return value


def _validate_minimum(name: str, value: int, minimum: int) -> int:
    """Validate a numeric lower bound for direct Python callers."""
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


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
        config = get_config()
        # Idempotent: sets XDG/JVM env and returns the resolved home. We do NOT
        # write it back into the (frozen) config -- serve_cmd persists the
        # resolved runtime_home before go-live so downstream reads still see it.
        resolved_runtime_home = _ensure_runtime_environment(config.project_dir, config.runtime_home)
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
    """Resolve and enforce restrict-path policy for imports.

    Returns the fully resolved, canonical path (all symlinks collapsed). Callers
    must use this resolved path for the actual import: because it is canonical,
    re-opening it cannot be redirected by swapping a symlink component after the
    check (the restricted-root decision is made on the real target). When the
    resolved target lies outside every restricted root, the error reports both
    the requested path and where it resolved to, so a blocked symlink is obvious.
    """
    requested = Path(path).expanduser()
    resolved = requested.resolve()
    restrict_roots = get_config().resolved_restrict_paths()
    if not restrict_roots:
        return resolved
    for root in restrict_roots:
        try:
            if resolved.is_relative_to(root):
                return resolved
        except ValueError:
            continue
    raise ValueError(
        f"Path not allowed: requested={requested}, resolves_to={resolved} "
        "(outside restricted directories)."
    )


def _unit_id_for(p: Path) -> str:
    """Compute (or reuse a cached) content-hash unit_id for a file.

    compute_unit_id_streaming reads the entire file -- expensive for large
    binaries and previously paid on every load(), even cache hits. Key the cache
    on (resolved path, mtime_ns, size): if any of those change the file is
    re-hashed, so a modified binary never reuses a stale id.
    """
    st = p.stat()
    key = (str(p), st.st_mtime_ns, st.st_size)
    with _unit_id_cache_lock:
        cached = _unit_id_cache.get(key)
    if cached is not None:
        return cached
    unit_id = compute_unit_id_streaming(p)
    with _unit_id_cache_lock:
        if len(_unit_id_cache) >= _UNIT_ID_CACHE_MAX:
            _unit_id_cache.clear()  # simple bounded reset; recomputation is rare
        _unit_id_cache[key] = unit_id
    return unit_id


def _assert_within_restrict_roots(p: Path) -> None:
    """Re-check that an already-resolved path is inside the restrict roots.

    Defense-in-depth against a time-of-check/time-of-use swap between resolving
    the import path and actually importing it: re-resolve right before use and
    confirm containment still holds. No-op when no roots are configured.
    """
    restrict_roots = get_config().resolved_restrict_paths()
    if not restrict_roots:
        return
    resolved = p.resolve()
    for root in restrict_roots:
        try:
            if resolved.is_relative_to(root):
                return
        except ValueError:
            continue
    raise ValueError(
        f"Path not allowed: {resolved} (outside restricted directories)."
    )


def _iter_disk_status():
    """Yield (project_id, enriched_status_dict) for every valid .analysis_status file on disk."""
    projects_path = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)
    if not projects_path.exists():
        return
    for entry in projects_path.iterdir():
        if not entry.is_dir():
            continue
        status_file = entry / ".analysis_status"
        try:
            fd = os.open(str(status_file), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        try:
            with os.fdopen(fd, "r") as f:
                status = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        project_id = entry.name
        parsed = parse_analysis_id(project_id)
        profile = status.get("profile")
        if parsed is not None:
            unit_id = parsed[0]
            profile = profile or parsed[1]
            analysis_id = project_id
        elif _UNIT_ID_RE.match(project_id):
            unit_id = project_id
            profile = profile or AnalysisProfile.FAST.value
            analysis_id = make_analysis_id(unit_id, profile)
        else:
            continue

        enriched = dict(status)
        enriched.setdefault("unit_id", unit_id)
        enriched.setdefault("analysis_id", analysis_id)
        enriched.setdefault("project_id", project_id)
        enriched.setdefault("profile", profile)
        yield project_id, enriched


def _history_path() -> Path:
    return Path(get_config().project_dir or DEFAULT_PROJECT_DIR) / "history.jsonl"


def _append_history(analysis_id: str, binary_name: str) -> None:
    """Append one open event to history.jsonl (non-blocking, best-effort)."""
    from datetime import datetime, timezone
    parsed = parse_analysis_id(analysis_id)
    entry = {
        "analysis_id": analysis_id,
        "unit_id": parsed[0] if parsed is not None else analysis_id,
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


def _last_opened_by_analysis_id() -> dict[str, str]:
    """Read history.jsonl and return {analysis_id: most_recent_opened_at ISO string}."""
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
                analysis_id = entry.get("analysis_id") or entry.get("unit_id", "")
                opened_at = entry.get("opened_at", "")
                # Lines are chronological; later lines overwrite earlier ones
                if analysis_id and opened_at:
                    result[analysis_id] = opened_at
            except json.JSONDecodeError:
                continue
    except OSError:
        pass
    return result


def _find_on_disk(binary: str, profile: str | None = None) -> dict | None:
    """Return metadata for a completed on-disk project matching binary.

    Accepts exact analysis_id, unit_id, or binary filename.
    When profile is provided, it is used to disambiguate multiple analyses of the same binary.
    Raises ValueError for in-progress/errored unit_ids.
    For ambiguous filename matches, logs a warning and selects never-opened first,
    then most-recently-opened.
    Used by _get_handle to auto-lazy-load programs that exist on disk but aren't loaded.
    """
    projects_path = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)
    if not projects_path.exists():
        return None

    parsed = parse_analysis_id(binary)
    if parsed is not None:
        unit_id, parsed_profile = parsed
        for _project_id, data in _iter_disk_status():
            if data.get("analysis_id") != binary:
                continue
            status = data.get("status")
            if status == "complete":
                return data
            if status in ("analyzing", "queued"):
                raise ValueError(
                    f"Analysis {binary!r} found but status={status!r}. "
                    "Poll binaries(jobs=True) and match analysis_id for progress."
                )
            # A prior attempt errored: don't treat it as a permanent tombstone --
            # return no match so the caller re-imports. Still visible via binaries().
            return None

    # Fast path: exact unit_id match
    if _UNIT_ID_RE.match(binary):
        matches: list[dict] = []
        for _project_id, data in _iter_disk_status():
            if data.get("unit_id") != binary:
                continue
            if profile is not None and data.get("profile") != profile:
                continue
            status = data.get("status")
            if status == "complete":
                matches.append(data)
                continue
            if status in ("analyzing", "queued"):
                raise ValueError(
                    f"Unit {binary!r} found but status={status!r}. "
                    "Poll binaries(jobs=True) and match unit_id for progress."
                )
            # A prior attempt errored: skip it rather than raising forever; the caller
            # re-imports and binaries() still surfaces the failure.
            continue
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            if profile is not None:
                raise ValueError(f"Multiple analyses found for unit {binary!r} and profile {profile!r}")
            raise ValueError(
                f"Multiple analyses found for unit {binary!r}. Use analysis_id or full program name from binaries()."
            )
        return None

    # Slow path: exact basename match against binary_name
    binary_base = Path(binary).name
    matches: list[dict] = []
    for _project_id, data in _iter_disk_status():
        if profile is not None and data.get("profile") != profile:
            continue
        if data.get("status") == "complete" and data.get("binary_name", "") == binary_base:
            matches.append(data)

    if len(matches) > 1:
        # Sort: never-opened (brand new) first, then by most recently opened per history.
        last_opened = _last_opened_by_analysis_id()
        matches.sort(
            key=lambda t: (
                last_opened.get(t["analysis_id"]) is None,
                last_opened.get(t["analysis_id"]) or "",
            ),
            reverse=True,
        )
        chosen = matches[0]["analysis_id"]
        others = [data["analysis_id"] for data in matches[1:]]
        logger.warning(
            "Ambiguous name %r: %d projects match. Picking preferred project %r"
            " (never-opened first, then most recently opened). Others: %s",
            binary, len(matches), chosen, others,
        )
        return matches[0]
    return matches[0] if matches else None


def _handle_by_analysis_id(backend: GhidraBackend, analysis_id: str):
    for handle in backend.programs.values():
        if _handle_analysis_id(handle) == analysis_id:
            return handle
    return None


def _handle_analysis_id(handle) -> str:
    """Best-effort profile-scoped id for real and mocked ProgramHandles."""
    analysis_id = getattr(handle, "analysis_id", None)
    if isinstance(analysis_id, str) and analysis_id:
        return analysis_id

    unit_id = getattr(handle, "unit_id", None)
    if not isinstance(unit_id, str) or not unit_id:
        return ""

    profile = getattr(handle, "profile", None)
    if isinstance(profile, AnalysisProfile):
        return make_analysis_id(unit_id, profile)
    if isinstance(profile, str) and profile:
        return make_analysis_id(unit_id, profile)
    return unit_id


def _touch_access(handle) -> None:
    """Update last-access timestamp for eviction tracking."""
    aid = getattr(handle, "analysis_id", None)
    if aid:
        _last_access[aid] = time.monotonic()
        _evicted_ids.discard(aid)


def _get_handle(binary: str, profile: str | None = None):
    backend = get_backend()
    handle = _handle_by_analysis_id(backend, binary)
    if handle is not None:
        _touch_access(handle)
        return handle

    if _UNIT_ID_RE.match(binary):
        loaded_matches = [
            handle for handle in backend.programs.values()
            if handle.unit_id == binary and (profile is None or handle.profile.value == profile)
        ]
        if len(loaded_matches) == 1:
            _touch_access(loaded_matches[0])
            return loaded_matches[0]
        if len(loaded_matches) > 1:
            raise ValueError(
                f"Multiple loaded analyses found for unit {binary!r}. Use analysis_id or full program name from binaries()."
            )

    try:
        h = backend.get_program(binary)
        _touch_access(h)
        return h
    except ValueError:
        pass

    # Auto-lazy-load: find a completed project on disk by analysis_id, unit_id, or filename
    # (raises ValueError for in-progress/ambiguous -- let that propagate)
    disk_match = _find_on_disk(binary, profile=profile)
    if disk_match:
        analysis_id = disk_match["analysis_id"]
        loaded = _hot_load_blocking(analysis_id)  # RLock allows reentry; one-time cost per session
        handle = _handle_by_analysis_id(backend, analysis_id)
        if handle is not None:
            _touch_access(handle)
            return handle
        if loaded:
            raise RuntimeError(
                f"Hot-loaded {analysis_id!r} but program not found in backend; "
                "internal name mismatch -- try the full program name from binaries()"
            )
        raise RuntimeError(f"Hot-load failed for {analysis_id!r}; check server logs")

    # Nothing found
    raise ValueError(f"Binary not found: {binary!r}. Use binaries() to list available names and IDs.")


def _handle_by_unit_id(backend: GhidraBackend, unit_id: str):
    for handle in backend.programs.values():
        if handle.unit_id == unit_id:
            return handle
    return None


def _load_project_into_backend(
    backend: GhidraBackend,
    analysis_id: str,
    *,
    update_capabilities: bool = False,
    append_history: bool = False,
):
    """Load a completed on-disk project into the provided backend."""
    handle = _handle_by_analysis_id(backend, analysis_id)
    if handle is not None:
        return handle

    status = _find_on_disk(analysis_id)
    if status is None:
        return None
    project_id = status["project_id"]
    unit_id = status["unit_id"]
    profile = AnalysisProfile(status["profile"])
    project_dir = Path(get_config().project_dir or DEFAULT_PROJECT_DIR) / project_id
    if not project_dir.exists():
        return None

    try:
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        project_str = str(project_dir.absolute())
        locator = ProjectLocator(project_str, project_id)
        if not locator.exists():
            logger.warning("Ghidra project missing for analysis_id=%s at %s", analysis_id, project_dir)
            return None

        project = GhidraProject.openProject(project_str, project_id, True)
        backend._projects[analysis_id] = project

        root_folder = project.getRootFolder()
        for domain_file in root_folder.getFiles():
            if str(domain_file.getContentType()) != "Program":
                continue
            prog_name = domain_file.getName()
            program = project.openProgram("/", prog_name, False)
            handle = backend._init_program_handle(program, prog_name, profile=profile, unit_id=unit_id)
            handle.analyzed = True
            backend.programs[prog_name] = handle
            if update_capabilities:
                _ensure_capabilities(handle)
            if append_history:
                binary_name = status.get("binary_name", prog_name)
                _append_history(analysis_id, binary_name)
            logger.info("Loaded %s from project cache (analysis_id=%s)", prog_name, analysis_id)
            return handle

        logger.warning("No Program entries found in project %s", analysis_id)
        return None
    except Exception as exc:
        logger.error("Failed to load project %s into backend: %s", analysis_id, exc)
        return None


def _resolve_bootstrap_handle(backend: GhidraBackend, bootstrap: str):
    """Resolve a bootstrap source by program name, analysis_id, binary name, or unit_id."""
    handle = _handle_by_analysis_id(backend, bootstrap)
    if handle is not None:
        return handle

    handle = _handle_by_unit_id(backend, bootstrap)
    if handle is not None:
        return handle

    try:
        return backend.get_program(bootstrap)
    except ValueError:
        pass

    disk_match = _find_on_disk(bootstrap)
    if disk_match:
        handle = _load_project_into_backend(backend, disk_match["analysis_id"])
        if handle is not None:
            return handle
        raise RuntimeError(f"Bootstrap source {bootstrap!r} exists on disk but could not be loaded")

    raise ValueError(f"Bootstrap source not found: {bootstrap!r}. Use binaries() to list available names.")


def _normalize_bootstrap_mode(mode: str) -> str:
    """Validate bootstrap mode."""
    return _validate_choice("bootstrap_mode", mode, ("named", "all"))


def _is_bootstrap_auto_name(name: str) -> bool:
    """True when a function name is a synthetic bootstrap label."""
    return name.startswith(f"{_BOOTSTRAP_AUTO_PREFIX}_")


def _normalize_bootstrap_source(bootstrap: str, dest_analysis_id: str) -> str:
    """Resolve and validate bootstrap source, returning its canonical analysis_id."""
    source_handle = _resolve_bootstrap_handle(get_backend(), bootstrap)
    if _handle_analysis_id(source_handle) == dest_analysis_id:
        raise ValueError("bootstrap source must differ from the destination binary")
    if not source_handle.analyzed:
        raise ValueError(f"Bootstrap source {bootstrap!r} is not analyzed yet")
    return _handle_analysis_id(source_handle)


def _apply_bootstrap_transfer(
    backend: GhidraBackend,
    source_binary: str,
    dest_handle,
    mode: str = "named",
) -> dict:
    """Transfer names from a bootstrap source to the destination handle."""
    mode = _normalize_bootstrap_mode(mode)
    source_handle = _resolve_bootstrap_handle(backend, source_binary)
    if _handle_analysis_id(source_handle) == _handle_analysis_id(dest_handle):
        raise ValueError("bootstrap source must differ from the destination binary")
    if not source_handle.analyzed:
        raise ValueError(f"Bootstrap source {source_binary!r} is not analyzed yet")
    if not dest_handle.analyzed:
        raise ValueError("Destination binary must be analyzed before bootstrap can run")
    stats = backend.transfer_analysis(
        source_handle.name,
        dest_handle.name,
        label_fun_star=(mode == "all"),
        fun_star_prefix=_BOOTSTRAP_AUTO_PREFIX,
    )
    stats["mode"] = mode
    if mode == "all":
        stats["synthetic_prefix"] = _BOOTSTRAP_AUTO_PREFIX
    return stats


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


def _sanitize_error_text(text: str) -> str:
    """Redact server-side absolute paths from outward-facing error text.

    Internal exceptions (Ghidra/JVM, filesystem) frequently embed absolute paths
    that disclose the project-dir layout and the server's home directory to MCP
    clients -- a real concern for shared/network deployments. Replace the known
    server roots with placeholders; full, unredacted detail still goes to the
    logs via logger.exception.
    """
    cfg = get_config()
    redactions: list[tuple[str, str]] = []

    def add_root(value, repl: str) -> None:
        # Exceptions report absolute paths, so redact the resolved form. Keep the
        # raw configured form too in case it appears verbatim (e.g. a relative
        # --project-dir like ./projects echoed back before resolution).
        if not value:
            return
        raw = Path(value)
        forms = {str(raw)}
        with suppress(RuntimeError, OSError):
            forms.add(str(raw.expanduser().resolve()))
        for form in forms:
            redactions.append((form, repl))

    add_root(cfg.project_dir or DEFAULT_PROJECT_DIR, "<project-dir>")
    add_root(cfg.runtime_home, "<runtime-home>")
    with suppress(RuntimeError, OSError):
        add_root(Path.home(), "~")
    # Longest needle first so nested roots (project-dir under home) redact fully.
    for needle, repl in sorted(redactions, key=lambda r: len(r[0]), reverse=True):
        if needle and needle not in ("/", "") and needle in text:
            text = text.replace(needle, repl)
    return text


def _guarded_tool_call(action: str, op):
    try:
        return op()
    except (ValueError, RuntimeError):
        raise
    except Exception as exc:
        logger.exception("%s failed", action)
        raise RuntimeError(f"{action} failed: {_sanitize_error_text(str(exc))}") from exc


def _with_handle(action: str, binary: str, op):
    with _backend_lock:
        return _guarded_tool_call(action, lambda: op(_get_handle(binary)))


async def _with_handle_async(action: str, binary: str, op):
    """Run a blocking handle operation off the event loop.

    Ghidra/JVM work (decompilation, reference walking, section iteration) is
    synchronous and can take seconds. Executing it directly in an async tool
    body would block the whole server -- under the shared HTTP transport a
    single decompile would freeze progress notifications and every other
    client's request. Offloading to a worker thread keeps the loop responsive;
    `_backend_lock` still serializes JVM access across threads.
    """
    return await asyncio.to_thread(_with_handle, action, binary, op)


def _tools_for(handle) -> GhidraTools:
    """Return a per-handle GhidraTools, reusing its caches across calls.

    GhidraTools builds a function-name index and caches function/symbol lists
    (with a TTL). The code used to do ``GhidraTools(handle)`` fresh on every
    info/code/functions/xrefs/search call, which threw those caches away each
    time and forced a full getFunctions() walk on every name lookup. Caching it
    on the handle lets the index survive between calls; it is discarded
    automatically when the handle is evicted and reloaded (a new handle object).
    """
    # Read/write through __dict__ so the cache key never collides with attribute
    # auto-vivification (e.g. MagicMock handles in tests) and so a handle without
    # a writable __dict__ simply falls back to a fresh instance.
    d = getattr(handle, "__dict__", None)
    if d is not None and "_tools_cache" in d:
        return d["_tools_cache"]
    cached = GhidraTools(handle)
    if d is not None:
        d["_tools_cache"] = cached
    return cached


def _locked_tools(handle, work):
    """Run a blocking GhidraTools operation under _backend_lock.

    The other read tools hold _backend_lock for their whole op (via
    _with_handle), so JVM access is serialized across worker threads. search
    resolves its handle off-lock for metadata, but its actual Ghidra calls must
    take the same lock so concurrent worker threads never touch the JVM at once.
    """
    with _backend_lock:
        return work(_tools_for(handle))


def _rank_sources_blocking(exclude_name: str | None = None) -> list[dict]:
    """Rank loaded+analyzed binaries by transferable named function count.

    Tracks both meaningful names and synthetic bootstrap labels. Sorting uses the
    transferable count, which includes either category and therefore better
    reflects how useful a source binary is for future bootstrap runs.
    Results are sorted descending -- index 0 is the richest source.

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
        meaningful_named = 0
        synthetic_named = 0
        for func in fm.getFunctions(True):
            name = func.getName()
            if name.startswith(("FUN_", "thunk_FUN_")):
                continue
            if _is_bootstrap_auto_name(name):
                synthetic_named += 1
            else:
                meaningful_named += 1
        transferable = meaningful_named + synthetic_named
        results.append({
            "name": handle.name,
            "unit_id": handle.unit_id,
            "total_functions": total,
            "named_functions": meaningful_named,
            "synthetic_bootstrap_functions": synthetic_named,
            "transferable_functions": transferable,
            "named_pct": round(meaningful_named / total * 100, 1) if total else 0.0,
            "transferable_pct": round(transferable / total * 100, 1) if total else 0.0,
        })

    results.sort(key=lambda r: (r["transferable_functions"], r["named_functions"]), reverse=True)
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

        # Resolve name -> handle -> unit_id
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
    projects_dir = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)
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

    # Start memory eviction monitor (unloads idle binaries from JVM, keeps on disk)
    eviction_task = asyncio.create_task(_eviction_monitor(interval=60))

    try:
        yield
    finally:
        stale_task.cancel()
        eviction_task.cancel()
        if observer:
            observer.stop()
            observer.join(timeout=2)
        with _backend_lock:
            if _backend:
                _backend.close()
                _backend = None
            _capabilities.clear()
            _last_access.clear()
            _evicted_ids.clear()


mcp = FastMCP("pyghidra-lite", lifespan=server_lifespan)


# =============================================================================
# TOOL ANNOTATIONS (MCP spec behavioral hints for clients/users)
# =============================================================================
# Per the MCP tool-annotations guidance, every tool advertises whether it is
# read-only, destructive, idempotent, and whether it touches the outside world.
# These are advisory hints (untrusted by spec) but let clients render safe
# auto-approve / confirmation UX. All pyghidra-lite tools operate on locally
# loaded binaries (no internet), so openWorldHint is False throughout.

def _read_only(title: str) -> ToolAnnotations:
    """Annotations for a read-only, idempotent analysis tool.

    Never mutates the binary, on-disk project, or server state; repeated calls
    with the same arguments return the same result.
    """
    return ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )


def _write_annotation(title: str) -> ToolAnnotations:
    """Annotations for an opt-in, human-confirmed write tool (annotate).

    Mutates the in-memory program and the on-disk project, so it is not
    read-only. destructiveHint is False (rename/comment/prototype are reversible
    relabelings, not data loss); idempotentHint is False because applying a
    prototype/comment can differ from the prior value. openWorldHint stays False
    -- writes only touch locally loaded binaries, never the network.
    """
    return ToolAnnotations(
        title=title,
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )


# Reject control characters and absurd lengths in a new symbol name. Ghidra
# itself accepts most strings, so this is a light guard, not a parser.
_SYMBOL_NAME_MAX = 255


def _validate_symbol_name(name: str) -> str:
    """Validate a user-supplied symbol name for the annotate(rename) action."""
    stripped = name.strip()
    if not stripped:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="name must be non-empty"))
    if len(stripped) > _SYMBOL_NAME_MAX:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"name too long (max {_SYMBOL_NAME_MAX} chars)",
        ))
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in stripped):
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="name must not contain control characters",
        ))
    return stripped


# =============================================================================
# ASYNC ANALYSIS HELPERS
# =============================================================================

def _read_status_file(project_id: str) -> dict:
    """Read .analysis_status for an on-disk project directory, returning {} on failure."""
    try:
        _validate_project_id(project_id)
    except ValueError:
        return {}
    status_file = Path(get_config().project_dir or DEFAULT_PROJECT_DIR) / project_id / ".analysis_status"
    try:
        fd = os.open(str(status_file), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return {}
    try:
        with os.fdopen(fd, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_status_file(project_id: str, data: dict):
    """Atomic write of .analysis_status for a project directory."""
    project_dir = _safe_project_path(
        Path(get_config().project_dir or DEFAULT_PROJECT_DIR), project_id
    )
    project_dir.mkdir(parents=True, exist_ok=True)
    status_file = project_dir / ".analysis_status"
    tmp = status_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=None))
    tmp.rename(status_file)


def _write_job_result(job_id: str, data: dict):
    """Atomic write of result.json for a scan job. Mirrors _write_status_file."""
    if not _UNIT_ID_RE.match(job_id):
        raise ValueError(f"Invalid job_id: {job_id!r}")
    d = Path(get_config().project_dir or DEFAULT_PROJECT_DIR) / job_id
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
    result_file = Path(get_config().project_dir or DEFAULT_PROJECT_DIR) / job_id / "result.json"
    if not result_file.exists():
        status = _active_jobs.get(job_id, {}).get("status", "not_found")
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Job {job_id!r} result not available (status={status!r}). "
                    "Poll binaries(jobs=True) until complete.",
        ))
    try:
        fd = os.open(str(result_file), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR,
                                 message=f"Failed to read result for {job_id!r}: {e}")) from e
    try:
        with os.fdopen(fd, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR,
                                 message=f"Failed to read result for {job_id!r}: {e}")) from e


def _bootstrap_meta(
    source_analysis_id: str | None,
    stats: dict | None = None,
    mode: str | None = None,
) -> dict | None:
    """Return a stable bootstrap payload for MCP responses."""
    if not source_analysis_id:
        return None
    parsed = parse_analysis_id(source_analysis_id)
    result = {"source_analysis_id": source_analysis_id}
    if parsed is not None:
        result["source_unit_id"] = parsed[0]
        result["source_profile"] = parsed[1]
    elif _UNIT_ID_RE.match(source_analysis_id):
        result["source_unit_id"] = source_analysis_id
    if mode:
        result["mode"] = mode
    if stats:
        result["stats"] = stats
        if "mode" in stats:
            result["mode"] = stats["mode"]
    return result


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


def _merge_live_job_entry(analysis_id: str, job: dict, *, include_jobs_meta: bool) -> dict:
    """Build a binaries() entry from in-memory job data plus live status file fields."""
    entry = {
        "unit_id": job.get("unit_id") or analysis_id,
        "analysis_id": analysis_id,
        "name": job.get("binary_name", analysis_id),
        "status": job.get("status", "unknown"),
        "profile": job.get("profile"),
    }
    bootstrap_meta = _bootstrap_meta(
        job.get("bootstrap_source"),
        mode=job.get("bootstrap_mode"),
    )
    if bootstrap_meta:
        entry["bootstrap"] = bootstrap_meta

    if not include_jobs_meta:
        return entry

    status_data = _read_status_file(job.get("project_id", analysis_id)) if job.get("kind") != "scan" else {}
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
    ):
        if key in status_data:
            entry[key] = status_data[key]

    status_bootstrap = status_data.get("bootstrap")
    if isinstance(status_bootstrap, dict):
        status_source = (
            status_bootstrap.get("source_analysis_id")
            or status_bootstrap.get("source_unit_id")
            or job.get("bootstrap_source")
        )
        status_stats = status_bootstrap.get("stats")
        status_mode = status_bootstrap.get("mode") or job.get("bootstrap_mode")
        if status_stats is None and "source_unit_id" not in status_bootstrap and "source_analysis_id" not in status_bootstrap:
            status_stats = status_bootstrap
        entry["bootstrap"] = _bootstrap_meta(status_source, status_stats, mode=status_mode)
    elif bootstrap_meta:
        entry["bootstrap"] = bootstrap_meta

    eta_sec = _compute_job_eta_sec(job, status_data)
    if eta_sec is not None:
        entry["eta_sec"] = eta_sec

    if job.get("kind") == "scan" and job.get("status") == "complete":
        try:
            entry["result"] = _get_job_result(analysis_id)
        except McpError:
            entry["result_available"] = False
        else:
            entry["result_available"] = True
        entry["hint"] = "Poll binaries(jobs=True); completed scan jobs include result when available."

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


async def _run_worker(path: Path, analysis_id: str, profile: str, job: dict):
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
            "--project-dir", str(get_config().project_dir or DEFAULT_PROJECT_DIR),
            "--jvm-heap", f"{heap_mb}m",
        ]
        if job.get("bootstrap_source"):
            cmd.extend(["--bootstrap", str(job["bootstrap_source"])])
            cmd.extend(["--bootstrap-mode", str(job.get("bootstrap_mode", "named"))])

        if get_config().ghidra_dir:
            cmd.extend(["--ghidra-dir", str(get_config().ghidra_dir)])
        if get_config().runtime_home:
            cmd.extend(["--runtime-home", str(get_config().runtime_home)])

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
                    status_data = _read_status_file(job.get("project_id", analysis_id))
                    stderr = str(status_data.get("error", "Worker exited with non-zero status"))
                job["status"] = "error"
                job["error"] = stderr[-500:]

        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)

        # Deferred pop: keep terminal status available for 5 min so callers can poll.
        asyncio.get_running_loop().call_later(300, _active_jobs.pop, analysis_id, None)


async def _run_import_inprocess(path: Path, analysis_id: str, profile: str, job: dict):
    """Run a large-binary analysis IN-PROCESS as a background task.

    Replaces the subprocess worker (_run_worker). The serve's OWN JVM does the
    import+analyze via _do_import_blocking, so:
      - the analyzed program ends up live in backend.programs -- no cross-process
        project handoff, so later tools never have to openProject a dir written by
        another process (that handoff is what wedges under Ghidra 12), and
      - there is no throwaway JVM to hang on shutdown, so no zombie worker / held
        project / forced kill.
    The model still gets an immediate "queued" result from load(); progress and the
    terminal result are published to the same .analysis_status file the subprocess
    used (via AnalysisProgressListener), so binaries(jobs=True) is unchanged.

    Heap/JVM are the serve's own (not per-binary tuned); the analyzeAll runs off
    _backend_lock (see _do_import_blocking) so other tool calls aren't frozen for the
    whole analysis, matching the existing small-binary in-process path.
    """
    global _worker_semaphore
    if _worker_semaphore is None:
        _worker_semaphore = asyncio.Semaphore(4)

    async with _worker_semaphore:
        job["status"] = "analyzing"
        profile_enum = AnalysisProfile(profile)
        project_id = job.get("project_id", analysis_id)
        status_path = _safe_project_path(
            Path(get_config().project_dir or DEFAULT_PROJECT_DIR), project_id
        ) / ".analysis_status"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        listener = AnalysisProgressListener(
            status_path, job["binary_name"], profile, path.stat().st_size,
            unit_id=job.get("unit_id"), analysis_id=analysis_id, binary_path=str(path),
        )
        tracker = ProgressTracker(message="importing")
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(
            _import_executor,
            lambda: _do_import_blocking(
                path, profile_enum, True, tracker,
                fresh=False,
                bootstrap=job.get("bootstrap_source"),
                bootstrap_mode=job.get("bootstrap_mode", "named"),
            ),
        )
        try:
            # Mirror in-thread progress into the status file while analysis runs.
            while not fut.done():
                progress, _total, message = tracker.get()
                listener.set_phase(message or "analyzing", round(progress / 100.0, 3))
                await asyncio.sleep(2)
            handle, caps, bootstrap_stats = await fut
            func_count = handle.program.getFunctionManager().getFunctionCount()
            cap_list = _format_capabilities(caps)
            bootstrap_meta = (
                _bootstrap_meta(
                    job.get("bootstrap_source"), bootstrap_stats,
                    mode=job.get("bootstrap_mode", "named"),
                )
                if bootstrap_stats else None
            )
            listener.complete(func_count, cap_list, bootstrap=bootstrap_meta)
            (job.update({"status": "complete", "functions": func_count}))
        except Exception as e:
            logger.exception("in-process analysis failed for %s", analysis_id)
            listener.error(str(e), "analyzing")
            (job.update({"status": "error", "error": str(e)[:500]}))

        # Deferred pop: keep terminal status available for 5 min so callers can poll.
        asyncio.get_running_loop().call_later(300, _active_jobs.pop, analysis_id, None)


async def _run_scan_task(job_id: str, job: dict, fn):
    """Run a blocking scan function in the thread pool; write result.json on completion.

    Used by batch_search_strings(background=True) and extract_bunfs().
    On completion, job status transitions to "complete" and result is persisted to disk.
    MCP clients should poll binaries(jobs=True); completed scan jobs include result data.
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


def _hot_load_blocking(analysis_id: str) -> bool:
    """Load a completed project into the running backend (blocking, runs in thread pool).

    Returns True if the program is now in backend.programs (loaded here or already loaded),
    False if it could not be loaded.
    """
    with _backend_lock:
        if _backend is None:
            return False
        handle = _load_project_into_backend(
            _backend,
            analysis_id,
            update_capabilities=True,
            append_history=True,
        )
        return handle is not None


async def _hot_load(analysis_id: str) -> None:
    """Async wrapper: hot-load a completed project into the backend."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(_import_executor, _hot_load_blocking, analysis_id)

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
        try:
            fd = os.open(str(status_path), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return
        try:
            with os.fdopen(fd, "r") as f:
                status = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        if status.get("status") != "complete":
            return

        project_id = status_path.parent.name
        try:
            _validate_project_id(project_id)
        except ValueError:
            return
        analysis_id = status.get("analysis_id")
        profile = status.get("profile")
        if not analysis_id:
            parsed = parse_analysis_id(project_id)
            if parsed is not None:
                analysis_id = project_id
            elif _UNIT_ID_RE.match(project_id):
                profile = profile or AnalysisProfile.FAST.value
                analysis_id = make_analysis_id(project_id, profile)
            else:
                return

        if not analysis_id:
            return

        with _backend_lock:
            if self.backend and any(
                _handle_analysis_id(h) == analysis_id or getattr(h, "unit_id", None) == project_id
                for h in list(self.backend.programs.values())
            ):
                return  # Already loaded

        if analysis_id in self._pending_hot_loads:
            return

        self._pending_hot_loads.add(analysis_id)
        try:
            # Schedule callback first; create coroutine/task on event loop thread.
            self.loop.call_soon_threadsafe(self._schedule_hot_load, analysis_id)
        except RuntimeError as e:
            self._pending_hot_loads.discard(analysis_id)
            logger.debug(f"Failed to schedule hot-load for {analysis_id}: {e}")

    def _schedule_hot_load(self, analysis_id: str) -> None:
        if self.loop.is_closed():
            self._pending_hot_loads.discard(analysis_id)
            return
        try:
            task = asyncio.create_task(self._async_hot_load(analysis_id))
            task.add_done_callback(lambda _t: self._pending_hot_loads.discard(analysis_id))
        except RuntimeError as e:
            self._pending_hot_loads.discard(analysis_id)
            logger.debug(f"Failed to create hot-load task for {analysis_id}: {e}")

    async def _async_hot_load(self, analysis_id: str):
        try:
            await _hot_load(analysis_id)
            logger.info(f"Watcher hot-loaded {analysis_id}")
        except Exception as e:
            logger.error(f"Watcher failed to hot-load {analysis_id}: {e}")
        finally:
            self._pending_hot_loads.discard(analysis_id)


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
    projects_path = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)
    if not projects_path.exists():
        return

    for entry in projects_path.iterdir():
        if not entry.is_dir():
            continue
        status_file = entry / ".analysis_status"
        if not status_file.exists():
            continue

        project_id = entry.name
        # Skip directories with unrecognized names
        try:
            _validate_project_id(project_id)
        except ValueError:
            continue
        with _backend_lock:
            status = _read_status_file(project_id)
            analysis_id = status.get("analysis_id")
            profile = status.get("profile")
            if not analysis_id:
                parsed = parse_analysis_id(project_id)
                if parsed is not None:
                    analysis_id = project_id
                elif _UNIT_ID_RE.match(project_id):
                    analysis_id = make_analysis_id(project_id, profile or AnalysisProfile.FAST.value)
            if _backend and any(
                _handle_analysis_id(h) == analysis_id or getattr(h, "unit_id", None) == project_id
                for h in list(_backend.programs.values())
            ):
                continue  # Already loaded by eager_load

        try:
            fd = os.open(str(status_file), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        try:
            with os.fdopen(fd, "r") as f:
                status = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        analysis_id = status.get("analysis_id") or analysis_id or project_id
        unit_id = status.get("unit_id") or (parse_analysis_id(analysis_id)[0] if parse_analysis_id(analysis_id) else project_id)

        if status.get("status") == "complete":
            continue  # Loaded lazily on first tool call via _get_handle/_find_on_disk

        pid = status.get("pid")
        alive = pid and _pid_alive(pid)

        if status.get("status") == "analyzing" and alive:
            # Worker still running from before restart -- track it
            job_entry = {
                "analysis_id": analysis_id,
                "unit_id": unit_id,
                "project_id": project_id,
                "binary_name": status.get("binary_name", unit_id),
                "profile": status.get("profile"),
                "status": "analyzing",
                "pid": pid,
                "recovered": True,
            }
            async with (_active_jobs_lock or nullcontext()):
                _active_jobs[analysis_id] = job_entry
            logger.info(f"Recovered in-progress job {analysis_id} (pid={pid})")

        elif status.get("status") in ("analyzing", "queued"):
            # Worker died -- mark failed
            status["status"] = "error"
            status["error"] = f"Worker process {pid} died (server restarted)"
            _write_status_file(project_id, status)
            logger.warning(f"Marked stale job {analysis_id} as error (pid={pid})")


async def _autopurge_stale_projects() -> None:
    """Delete on-disk projects whose last open was more than autopurge_days days ago.

    Brand-new analyses (never opened, no history entry) are always skipped -- they
    may be freshly analyzed and waiting for an agent to start working on them.
    """
    days = get_config().autopurge_days
    if not days or days <= 0:
        return

    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.isoformat()

    last_opened = _last_opened_by_analysis_id()
    project_base = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)

    purged = []
    for project_id, data in _iter_disk_status():
        if data.get("status") != "complete":
            continue
        analysis_id = data["analysis_id"]
        last_open = last_opened.get(analysis_id)
        if last_open is None:
            continue  # Never opened -- brand new, skip
        if last_open < cutoff_str:  # ISO UTC strings compare lexicographically
            try:
                with _backend_lock:
                    active_ids = set(get_backend()._projects.keys()) if _backend else set()
                if analysis_id in active_ids:
                    continue  # in-use -- skip purge
                shutil.rmtree(_safe_project_path(project_base, project_id))
                purged.append((analysis_id, data.get("binary_name", analysis_id)))
                logger.info("Autopurged %s (%s), last opened %s", data.get("binary_name", analysis_id), analysis_id, last_open)
            except OSError as e:
                logger.warning("Failed to autopurge %s: %s", analysis_id, e)

    if purged:
        logger.info("Autopurge complete: removed %d project(s)", len(purged))


async def _eviction_monitor(interval: int = 60):
    """Periodically evict idle binaries from memory to reduce JVM heap pressure.

    Binaries are unloaded from the JVM but kept on disk -- the next tool call
    referencing an evicted binary transparently reloads it via _get_handle().
    """
    evict_minutes = get_config().evict_after_minutes
    min_loaded = get_config().min_loaded
    if not evict_minutes or evict_minutes <= 0:
        return  # Eviction disabled

    evict_seconds = evict_minutes * 60
    logger.info(
        "Eviction monitor started: idle threshold %d min, keep at least %d loaded",
        evict_minutes, min_loaded,
    )

    while True:
        await asyncio.sleep(interval)
        with _backend_lock:
            if _backend is None:
                continue
            loaded_ids = [
                h.analysis_id
                for h in _backend.programs.values()
                if h.analysis_id
            ]
        if len(loaded_ids) <= min_loaded:
            continue

        now = time.monotonic()
        # Build (analysis_id, last_access) pairs; untracked binaries use load time 0
        # so they're evicted first
        scored = [(aid, _last_access.get(aid, 0.0)) for aid in loaded_ids]
        # Sort by most recent access (keep the freshest)
        scored.sort(key=lambda x: x[1], reverse=True)

        # Evict idle binaries beyond min_loaded
        candidates = scored[min_loaded:]  # protect the N most recent
        evicted = []
        for aid, last_ts in candidates:
            idle_sec = now - last_ts
            if idle_sec < evict_seconds:
                continue
            # Don't evict binaries with active analysis jobs
            with _jobs_mutex:
                if aid in _active_jobs and _active_jobs[aid].get("status") in ("queued", "analyzing", "running"):
                    continue
            with _backend_lock:
                if _backend is None:
                    break
                name = _backend.evict(aid)
                if name:
                    _last_access.pop(aid, None)
                    _evicted_ids.add(aid)
                    evicted.append(name)

        if evicted:
            logger.info("Evicted %d idle binary(ies): %s", len(evicted), ", ".join(evicted))


async def _stale_job_monitor(interval: int = 30):
    """Periodically check for crashed workers."""
    while True:
        await asyncio.sleep(interval)
        async with (_active_jobs_lock or nullcontext()):
            for analysis_id, job in list(_active_jobs.items()):
                if job.get("status") != "analyzing":
                    continue
                pid = job.get("pid")
                if pid and not _pid_alive(pid):
                    status_data = _read_status_file(job.get("project_id", analysis_id))
                    # Check if it actually completed (status file might say "complete")
                    if status_data.get("status") == "complete":
                        job["status"] = "complete"
                        continue
                    logger.warning(f"Stale job {analysis_id}: pid {pid} dead")
                    _write_status_file(job.get("project_id", analysis_id), {
                        "status": "error",
                        "error": f"Worker process {pid} died unexpectedly",
                        "phase": "unknown",
                    })
                    with _jobs_mutex:
                        _active_jobs.pop(analysis_id, None)


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
    bootstrap_mode: str = "named",
) -> tuple:
    """Blocking import operation (runs in thread pool).

    Lock scope is minimised: we hold _backend_lock only for the fast
    import_binary() call (which mutates backend.programs), then release
    it before the potentially long-running analyzeAll() so other MCP
    tool calls aren't blocked for the entire analysis duration.
    """
    tracker.update(10, "Loading file")

    # Re-validate containment right before import (TOCTOU defense-in-depth).
    _assert_within_restrict_roots(p)

    # Hold lock only for the import (mutates shared state)
    with _backend_lock:
        backend = get_backend()
        tracker.update(20, "Importing to Ghidra")
        handle = backend.import_binary(p, profile_enum, analyze=False, fresh=fresh)

    tracker.update(40, "Import complete")

    # Analysis runs outside the lock -- analyzeAll() operates on a
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
            bootstrap_stats = _apply_bootstrap_transfer(
                get_backend(),
                bootstrap,
                handle,
                mode=bootstrap_mode,
            )

    tracker.update(90, "Detecting capabilities")
    caps = _ensure_capabilities(handle)
    tracker.update(100, "Complete")

    return handle, caps, bootstrap_stats


# =============================================================================
# CONSOLIDATED TOOLS (8 tools replacing 58)
# =============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        title="Load Binary",
        readOnlyHint=False,  # imports the binary and creates an on-disk project
        destructiveHint=False,  # never deletes existing data (fresh re-imports in place)
        idempotentHint=False,  # may kick off analysis / transfer bootstrap names
        openWorldHint=False,  # operates on the local filesystem only
    )
)
async def load(
    path: NonEmptyStr,
    ctx: Context,
    profile: LoadProfileArg = "fast",
    analyze: bool = True,
    fresh: bool = False,
    bootstrap: NonEmptyStr | None = None,
    bootstrap_mode: BootstrapModeArg = "named",
) -> dict:
    """Load a binary into pyghidra-lite for reverse engineering. This is always
    the first tool to call - no other tool works until a binary is loaded.

    Small binaries (<10MB) block until analysis finishes and return full results.
    Large binaries (>=10MB) return immediately with a unit_id; poll progress with
    binaries(jobs=True).

    If you load a path that was previously analyzed, it returns from cache instantly
    with status="ready". To throw away a stale or wrong-profile analysis and start
    clean, pass fresh=True.

    Profile selection matters:
      - "fast" (default): skips 20 slow Ghidra analyzers. Good enough for function
        listing, string search, and on-demand decompilation. Use this for first contact.
      - "default": enables all analyzers except Decompiler Parameter ID. Better
        decompilation quality, ~10x slower than fast.
      - "deep": full Ghidra analysis including aggressive instruction finding. Use
        for obfuscated or packed binaries where fast/default miss functions.

    Version tracking: if you have a previously-analyzed reference binary loaded
    (e.g., an older version of the same app), pass bootstrap="reference-binary-name"
    to transfer function names via exact byte matching before analysis runs. This
    pre-labels known functions so the agent starts with meaningful names instead of
    FUN_* addresses. Use bootstrap_mode="all" to also create stable synthetic labels
    for unnamed functions - useful for tracking unnamed code across versions.

    Args:
        path: Path to binary file.
        profile: Analysis depth - "fast" (default), "default", or "deep".
        analyze: Run analysis (False = import only, faster).
        fresh: Discard cached analysis and re-import from scratch.
        bootstrap: Name of analyzed binary to transfer names from (version tracking).
        bootstrap_mode: "named" (default) transfers only semantic names; "all"
            also synthesizes stable labels for FUN_* functions.
    """
    try:
        p = _resolve_import_path(path)
    except ValueError:
        raise
    if not p.exists():
        raise ValueError(f"Not found: {p}")

    profile = _validate_choice("profile", profile, ("fast", "default", "deep"))
    profile_enum = AnalysisProfile(profile)

    with open(p, "rb") as f:
        header = f.read(16)

    kind = detect_binary_kind(p, header)
    file_size_mb = p.stat().st_size / (1024 * 1024)
    unit_id = _unit_id_for(p)
    analysis_id = make_analysis_id(unit_id, profile)
    bootstrap_source = None
    bootstrap_mode = _normalize_bootstrap_mode(bootstrap_mode)

    if bootstrap is None and bootstrap_mode != "named":
        raise ValueError("bootstrap_mode requires bootstrap")

    if bootstrap:
        _require_backend()
        with _backend_lock:
            bootstrap_source = _normalize_bootstrap_source(bootstrap, analysis_id)

    # Auto-delegate large binaries to async analysis to avoid MCP timeouts.
    if analyze and file_size_mb >= _LARGE_BINARY_MB:
        _require_backend()

        # fresh=True: purge everything before any caching checks so the
        # subsequent import and worker spawn always start from a clean slate.
        if fresh:
            with _backend_lock:
                if _backend:
                    _backend._purge_analysis(analysis_id)
            disk_match = _find_on_disk(unit_id, profile=profile)
            if disk_match:
                proj_path = _safe_project_path(
                    Path(get_config().project_dir or DEFAULT_PROJECT_DIR),
                    disk_match["project_id"],
                )
                if proj_path.exists():
                    shutil.rmtree(proj_path, onerror=_rmtree_warn)
            async with (_active_jobs_lock or nullcontext()):
                _kill_job(analysis_id)
            logger.info("fresh=True: purged all cached state for analysis_id=%s", analysis_id)

        # Already loaded in memory?
        if not fresh:
            with _backend_lock:
                loaded_handles = list(_backend.programs.values()) if _backend else []
            for h in loaded_handles:
                if h.analysis_id == analysis_id and h.analyzed:
                    caps = _ensure_capabilities(h)
                    result = {
                        "unit_id": unit_id,
                        "analysis_id": analysis_id,
                        "binary_name": p.name,
                        "kind": kind,
                        "profile": h.profile.value,
                        "status": "ready",
                        "functions": h.program.getFunctionManager().getFunctionCount(),
                        "capabilities": _format_capabilities(caps),
                    }
                    if bootstrap_source:
                        with _backend_lock:
                            stats = _apply_bootstrap_transfer(
                                get_backend(), bootstrap_source, h, mode=bootstrap_mode
                            )
                        result["bootstrap"] = _bootstrap_meta(bootstrap_source, stats)
                    return result

        # Check disk: already analyzed by a previous import run? (outside lock)
        disk_match = _find_on_disk(unit_id, profile=profile) if not fresh else None
        if not fresh and disk_match is not None:
            try:
                status_data = dict(disk_match)
                if status_data.get("status") == "complete":
                    # Hot-load into memory so it's immediately available
                    hot_load_error = None
                    try:
                        await _hot_load(disk_match["analysis_id"])
                    except Exception as e:
                        hot_load_error = str(e)
                    # Verify program actually loaded (hot-load can silently fail)
                    hot_loaded = False
                    with _backend_lock:
                        if _backend:
                            hot_loaded = any(
                                h.analysis_id == disk_match["analysis_id"] for h in _backend.programs.values()
                            )
                    result = {
                        "unit_id": unit_id,
                        "analysis_id": disk_match["analysis_id"],
                        "binary_name": p.name,
                        "kind": kind,
                        "profile": status_data.get("profile"),
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
                            dest_handle = _handle_by_analysis_id(get_backend(), disk_match["analysis_id"])
                            if dest_handle is not None:
                                stats = _apply_bootstrap_transfer(
                                    get_backend(),
                                    bootstrap_source,
                                    dest_handle,
                                    mode=bootstrap_mode,
                                )
                                result["bootstrap"] = _bootstrap_meta(bootstrap_source, stats)
                    return result
            except (json.JSONDecodeError, OSError):
                pass

        async with (_active_jobs_lock or nullcontext()):
            # Already in progress? (skip check when fresh -- we just cleared the job)
            if not fresh and analysis_id in _active_jobs:
                job = _active_jobs[analysis_id]
                if job.get("status") not in ("complete", "error"):
                    if bootstrap_source and job.get("bootstrap_source") != bootstrap_source:
                        raise ValueError(
                            f"Analysis already in progress for {p.name!r} with a different "
                            f"bootstrap source. Cancel with delete(unit_id='{unit_id}') "
                            "or retry with fresh=True."
                        )
                    if bootstrap_source and job.get("bootstrap_mode", "named") != bootstrap_mode:
                        raise ValueError(
                            f"Analysis already in progress for {p.name!r} with "
                            f"bootstrap_mode={job.get('bootstrap_mode', 'named')!r}. "
                            f"Cancel with delete(unit_id='{unit_id}') or retry with fresh=True."
                        )
                    entry = _merge_live_job_entry(analysis_id, job, include_jobs_meta=True)
                    entry["binary_name"] = p.name
                    entry["message"] = (
                        f"Analysis in progress ({file_size_mb:.0f}MB). "
                        f"Poll binaries(jobs=True) and match analysis_id='{analysis_id}'"
                    )
                    return entry
                # Terminal state stale entry: fall through and re-queue.

            # Guard against unbounded job accumulation.
            active_count = sum(
                1 for j in _active_jobs.values()
                if j.get("status") in ("queued", "analyzing")
            )
            if active_count >= _MAX_QUEUED_JOBS:
                raise ValueError(
                    f"Job queue full ({active_count} active). "
                    "Wait for current jobs to complete or cancel with delete()."
                )

            # Spawn in-process background analysis (no subprocess -> no zombie /
            # cross-process openProject wedge; see _run_import_inprocess).
            estimated = _estimate_analysis_time(p.stat().st_size, profile)
            job: dict = {
                "analysis_id": analysis_id,
                "project_id": analysis_id,
                "unit_id": unit_id,
                "binary_name": p.name,
                "status": "queued",
                "eta_sec": estimated,
                "profile": profile,
                "pid": None,
                "bootstrap_source": bootstrap_source,
                "bootstrap_mode": bootstrap_mode,
            }
            with _jobs_mutex:
                _active_jobs[analysis_id] = job
            asyncio.create_task(_run_import_inprocess(p, analysis_id, profile, job))
            result = {
                "unit_id": unit_id,
                "analysis_id": analysis_id,
                "binary_name": p.name,
                "kind": kind,
                "profile": profile,
                "status": "queued",
                "eta_sec": estimated,
                "message": (
                    f"Binary is {file_size_mb:.0f}MB; analysis runs in background. "
                    f"Poll binaries(jobs=True) and match analysis_id='{analysis_id}'"
                ),
            }
            bootstrap_meta = _bootstrap_meta(bootstrap_source, mode=bootstrap_mode)
            if bootstrap_meta:
                result["bootstrap"] = bootstrap_meta
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
                bootstrap_mode=bootstrap_mode,
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
            "analysis_id": handle.analysis_id,
            "kind": kind,
            "profile": handle.profile.value,
            "capabilities": _format_capabilities(caps),
            "status": "ready",
        }
        bootstrap_meta = _bootstrap_meta(bootstrap_source, bootstrap_stats)
        if bootstrap_meta:
            result["bootstrap"] = bootstrap_meta
        if handle.was_preexisting:
            result["note"] = "already_analyzed"

        return result
    except ValueError:
        raise
    except Exception as e:
        logger.exception("Import failed")
        raise RuntimeError(f"Import failed: {e}") from e


@mcp.tool(
    annotations=ToolAnnotations(
        title="Delete Binary",
        readOnlyHint=False,
        destructiveHint=True,  # permanently removes the project and any worker
        idempotentHint=True,  # deleting an already-removed binary is a no-op
        openWorldHint=False,
    )
)
async def delete(name: NonEmptyStr, ctx: Context) -> dict:
    """Permanently remove a binary, its on-disk Ghidra project, and any running
    analysis worker. Use this to free disk space, clean up failed analyses, or
    remove binaries you no longer need. Accepts a binary name, unit_id, or partial
    name match. For ambiguous matches, use the exact unit_id from binaries().

    Args:
        name: Binary name or unit_id.
    """
    def op():
        backend = get_backend()
        project_base = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)

        # Search loaded binaries without triggering auto-load
        handle = None
        exact = [h for h in backend.programs.values() if name in (h.name, h.unit_id, h.analysis_id)]
        partial = [h for h in backend.programs.values() if name in h.name] if not exact else []
        matches = exact or partial
        if len(matches) > 1:
            candidates = [f"{h.name} ({h.unit_id})" for h in matches]
            raise ValueError(
                f"Ambiguous match for {name!r}: {candidates}. Use exact name or unit_id."
            )
        handle = matches[0] if matches else None

        if handle is not None:
            unit_id = handle.unit_id
            analysis_id = handle.analysis_id
            _capabilities.pop(unit_id, None)
            deleted = backend.delete_program(handle.name)
            if not deleted:
                raise RuntimeError(f"Failed to delete {handle.name!r} from Ghidra project")
            _kill_job(analysis_id)
            project_id = analysis_id if (project_base / analysis_id).exists() else unit_id
            shutil.rmtree(_safe_project_path(project_base, project_id), onerror=_rmtree_warn)
            return {"deleted": handle.name, "unit_id": unit_id, "analysis_id": analysis_id}

        # Disk-only (errored, incomplete, never loaded)
        disk_match = _find_on_disk(name)
        if not disk_match:
            raise ValueError(f"Not found: {name!r}. Use analysis_id or exact name from binaries().")

        project_dir = _safe_project_path(project_base, disk_match["project_id"])
        if not project_dir.exists():
            raise ValueError(f"Project not found: {disk_match['project_id']!r}")

        binary_name = _read_status_file(disk_match["project_id"]).get("binary_name", disk_match["analysis_id"])
        _kill_job(disk_match["analysis_id"])
        shutil.rmtree(project_dir, onerror=_rmtree_warn)
        return {
            "deleted": binary_name,
            "unit_id": disk_match["unit_id"],
            "analysis_id": disk_match["analysis_id"],
        }

    with _backend_lock:
        return _guarded_tool_call("delete", op)


@mcp.tool(annotations=_read_only("List Binaries"))
async def binaries(
    ctx: Context,
    jobs: bool = False,
    rank_sources: bool = False,
) -> "list[dict]":
    """Show everything pyghidra-lite knows about: binaries loaded in memory,
    analyses currently running, queued jobs, and completed projects on disk from
    previous sessions. Use this to:

      - Find the exact binary name or unit_id needed by other tools.
      - Check whether a binary is already analyzed (avoid redundant load calls).
      - Monitor progress of large async analyses (pass jobs=True).
      - Find the best source binary for version tracking (pass rank_sources=True
        to sort by transferable named function count).

    Binaries listed as "on_disk" or "evicted" auto-load into memory the first
    time any tool references them - no need to re-import. Evicted binaries were
    previously loaded but unloaded to free memory after idle timeout; they reload
    transparently on the next tool call (e.g., code(), functions(), search()).

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
        seen_analysis_ids = set()
        with _jobs_mutex:
            active_jobs_snapshot = list(_active_jobs.items())

        # Currently loaded in memory
        for prog_name in backend.list_programs():
            handle = backend.get_program(prog_name)
            seen_analysis_ids.add(handle.analysis_id)
            caps = _ensure_capabilities(handle)
            results.append({
                "name": handle.name,
                "unit_id": handle.unit_id,
                "analysis_id": handle.analysis_id,
                "status": "ready",
                "profile": handle.profile.value if handle.profile else None,
                "capabilities": _format_capabilities(caps),
            })

        # In-progress analyses
        for job_key, raw_job in active_jobs_snapshot:
            job = dict(raw_job)
            if job.get("kind") == "scan":
                analysis_id = job_key
                job.setdefault("unit_id", job_key)
            else:
                unit_id = job.get("unit_id") or job_key
                profile_value = job.get("profile") or AnalysisProfile.FAST.value
                analysis_id = job.get("analysis_id") or (
                    make_analysis_id(unit_id, profile_value) if _UNIT_ID_RE.match(unit_id) else unit_id
                )
                job.setdefault("unit_id", unit_id)
                job.setdefault("analysis_id", analysis_id)
                if "project_id" not in job:
                    project_base = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)
                    if (project_base / job_key / ".analysis_status").exists():
                        job["project_id"] = job_key
                    elif (project_base / analysis_id / ".analysis_status").exists():
                        job["project_id"] = analysis_id
                    else:
                        job["project_id"] = job_key
            if analysis_id not in seen_analysis_ids:
                seen_analysis_ids.add(analysis_id)
                results.append(_merge_live_job_entry(analysis_id, job, include_jobs_meta=jobs))

        # On-disk projects not yet loaded
        projects_path = Path(get_config().project_dir or DEFAULT_PROJECT_DIR)
        if projects_path.exists():
            for _project_id, status_data in _iter_disk_status():
                analysis_id = status_data["analysis_id"]
                if analysis_id in seen_analysis_ids:
                    continue
                seen_analysis_ids.add(analysis_id)
                is_evicted = analysis_id in _evicted_ids
                disk_status = status_data.get("status", "on_disk")
                disk_entry = {
                    "unit_id": status_data["unit_id"],
                    "analysis_id": analysis_id,
                    "name": status_data.get("binary_name", analysis_id),
                    "status": "evicted" if is_evicted and disk_status == "complete" else disk_status,
                    "functions": status_data.get("functions"),
                    "capabilities": status_data.get("capabilities", []),
                    "profile": status_data.get("profile"),
                }
                if is_evicted and disk_status == "complete":
                    disk_entry["hint"] = "Idle-evicted from memory. Any tool call referencing this binary reloads it automatically."
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
                        "bootstrap",
                    ):
                        if key in status_data:
                            disk_entry[key] = status_data[key]
                results.append(disk_entry)

        return results

    with _backend_lock:
        return _guarded_tool_call("binaries", op)


@mcp.tool(annotations=_read_only("Binary Info"))
async def info(
    binary: NonEmptyStr,
    ctx: Context,
    detail: InfoDetailArg = "summary",
) -> dict:
    """Get a binary overview, from a quick summary to a full first-contact triage.
    **Call this right after load() to orient on an unfamiliar binary before diving
    into code or search.**

    The detail parameter controls how much work info does:

      - "summary" (default): format, arch, bits, endianness, function/symbol counts,
        and detected capabilities (swift/objc/elf/macho/hermes). Fast, minimal tokens.
        Use this when you just need to confirm what you're working with.

      - "full": complete triage in one call. Returns everything from summary plus:
        top functions ranked by reference count (likely entry points and core logic),
        suspicious imports tagged by capability (crypto, network, file, process),
        notable strings (URLs, keys, paths, error messages), detected embedded
        runtimes (Bun, Electron, Node, PyInstaller, UPX), and language-specific
        metadata (Swift module name, ObjC class/selector counts). **Use this as
        your first call on any unfamiliar binary - it replaces 5+ separate tool
        calls and tells you where to investigate next.**

      - "format": raw format-specific headers. Returns ELF details (debug info,
        stripped status, machine type), Mach-O details (CPU type, segment count,
        code signature, entrypoint), or PE details (machine, section/import/DLL
        counts, .NET detection). Use when you need format-level metadata beyond
        what summary provides.

      - "sections": full memory/section layout with addresses, sizes, and
        read/write/execute permissions. Use to understand the binary's memory map
        or find which section contains a given address.

      - "entropy": Shannon entropy per section. Sections >7.0 are likely encrypted
        or compressed; <1.0 is mostly zeros. Use to identify packed or encrypted
        regions before investing time decompiling them.

    Args:
        binary: Binary name or unit_id.
        detail: Level of detail:
            - "summary" (default): basic info + capabilities
            - "full": triage with top functions, imports, strings
            - "format": raw format headers (ELF/Mach-O/PE specific)
            - "sections": memory/section layout
            - "entropy": per-section entropy analysis
    """
    detail = _validate_choice("detail", detail, _INFO_DETAILS)

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

        tools = _tools_for(handle)

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
            elif caps.is_pe:
                from pyghidra_lite.formats import PeTools
                pe_info = PeTools(handle).get_pe_info()
                base["pe"] = {
                    "bits": pe_info.bits,
                    "endian": pe_info.endian,
                    "machine": pe_info.machine,
                    "num_sections": pe_info.num_sections,
                    "num_imports": pe_info.num_imports,
                    "num_dlls": pe_info.num_dlls,
                    "is_dotnet": pe_info.is_dotnet,
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

    return await _with_handle_async("info", binary, op)


@mcp.tool(annotations=_read_only("List Functions"))
async def functions(
    binary: NonEmptyStr,
    ctx: Context,
    query: str = "",
    type: FunctionsTypeArg = "all",
    limit: Annotated[int, Field(ge=1)] = 50,
    demangle: str = "",
) -> list[dict]:
    """List, search, or filter functions in a binary. This is the primary
    navigation tool for understanding what code exists and finding targets to
    decompile.

    The type parameter selects which view of the binary's symbols to show:

      - "all" (default): every function, sorted by name. Returns compact
        {name, addr} pairs. Filter with query= for substring matching. Start
        here when exploring an unfamiliar binary after running info(detail="full").

      - "swift": Swift functions with demangled human-readable names, kind
        classification (function/initializer/getter/setter/witness), and addresses.
        Only available when Swift code is detected. Use instead of "all" when
        working with iOS/macOS Swift binaries - "all" shows mangled names.

      - "objc": Objective-C methods with full signatures (-[Class selector]),
        class names, and addresses. Only available when ObjC code is detected.

      - "imports": imported functions with automatic capability tagging (crypto,
        network, file, process, memory, jni). Shows which system capabilities
        the binary uses and which libraries provide them. For PE binaries each
        row also includes the source DLL and its IAT/thunk address (iat_addr).

      - "exports": exported symbols - the binary's public API surface. Use to
        understand what a shared library exposes.

      - "types": Swift type definitions (structs, classes, enums) extracted from
        metadata sections. Use to understand the data model without decompiling.

      - "got": GOT/PLT entries showing dynamic linking targets (ELF only).

      - "dylibs": linked dynamic libraries (Mach-O only).

    To demangle a single Swift symbol without listing functions, pass demangle=
    with the mangled name (e.g., "_$s...").

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
    limit = _validate_minimum("limit", limit, 1)
    type = _validate_choice("type", type, _FUNCTION_TYPES)

    # Single symbol demangle shortcut
    if demangle:
        from pyghidra_lite.lang import demangle_swift
        return [{"mangled": demangle, "demangled": demangle_swift(demangle)}]

    def op(handle):
        tools = _tools_for(handle)
        caps = _ensure_capabilities(handle)

        if type == "swift":
            if not caps.has_swift:
                raise ValueError("Binary has no Swift code")
            from pyghidra_lite.lang import SwiftTools
            swift_tools = SwiftTools(handle)
            results = swift_tools.list_swift_functions(pattern=query, limit=limit)
            return [
                {"demangled": f.demangled, "address": f.address, "kind": f.kind}
                for f in results
            ]

        if type == "objc":
            if not caps.has_objc:
                raise ValueError("Binary has no Objective-C code")
            from pyghidra_lite.lang import ObjCTools
            objc_tools = ObjCTools(handle)
            methods = objc_tools.list_methods(pattern=query, limit=limit)
            return [
                {"signature": m.signature, "class": m.class_name, "address": m.impl_address}
                for m in methods
            ]

        if type == "imports":
            if caps.is_pe:
                # PE: use the ExternalManager-backed view so each import carries its
                # source DLL and IAT/thunk address. Flattened to the same shape as
                # other formats (one row per imported function).
                from pyghidra_lite.formats import PeTools
                grouped = PeTools(handle).list_imports_by_dll(pattern=query, limit=limit)
                return [
                    {"name": f["name"], "library": g["dll"],
                     "iat_addr": f.get("iat_addr"), "tags": f.get("tags") or []}
                    for g in grouped for f in g["functions"]
                ]
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
                raise ValueError("Binary has no Swift code")
            from pyghidra_lite.lang import SwiftTools
            swift_tools = SwiftTools(handle)
            types = swift_tools.list_swift_types(limit=limit)
            return [
                {"name": t.name, "module": t.module, "kind": t.kind}
                for t in types
            ]

        if type == "got":
            if not caps.is_elf:
                raise ValueError("GOT/PLT only available for ELF binaries")
            from pyghidra_lite.formats import ElfTools
            return ElfTools(handle).get_got_plt()

        if type == "dylibs":
            if not caps.is_macho:
                raise ValueError("dylibs only available for Mach-O binaries")
            from pyghidra_lite.formats import MachOTools
            return [{"name": d.name} for d in MachOTools(handle).list_dylibs()]

        # Default: all functions
        funcs = tools.list_functions(pattern=query, limit=limit)
        return [{"name": f.name, "addr": f.address} for f in funcs]

    results = await _with_handle_async("functions", binary, op)
    await _warn_if_limit_reached(ctx, "functions", limit, len(results))
    return results


@mcp.tool(annotations=_read_only("Read Code"))
async def code(
    binary: NonEmptyStr,
    target: CodeTargetArg,
    ctx: Context,
    what: CodeWhatArg = "decompile",
    cfg: bool = False,
) -> dict | list[dict]:
    """Read code from a binary. This is the core analysis tool - use it to
    understand what a function does.

    Default mode (what="decompile") returns pseudo-C source code for a function,
    along with its callers, callees, and referenced strings - all in one call.
    No need to make separate xrefs or search calls after decompiling.

    Pass a single function name or hex address (e.g., "main" or "0x4011a0") as
    target. Pass a list of names/addresses for batch decompilation - more
    efficient than repeated single calls.

    The what parameter selects output format:

      - "decompile" (default): pseudo-C with full context (callers, callees,
        strings). Add cfg=True to also get the control flow graph (basic blocks
        and edges) - useful for understanding loop structure and branch complexity,
        especially on fast-profile binaries where type inference is limited.

      - "asm": raw assembly instructions with mnemonics and operands. Use when
        decompilation fails, produces misleading output, or when you need to see
        exact instruction encoding.

      - "bytes": raw hex bytes at an address. Target format is "addr,size"
        (e.g., "0x4011a0,64"). Use to inspect data structures or verify byte patterns.

      - "string": read a null-terminated string at an address. Use when you need
        the full untruncated value of a string found via search.

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
    what = _validate_choice("what", what, _CODE_WHATS)

    def op(handle):
        tools = _tools_for(handle)

        # Handle batch decompile
        if isinstance(target, list):
            if what != "decompile":
                raise ValueError("Batch targets only support what='decompile'")
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

    return await _with_handle_async("code", binary, op)


@mcp.tool(annotations=_read_only("Cross-References"))
async def xrefs(
    binary: NonEmptyStr,
    target: XrefsTargetArg,
    ctx: Context,
    direction: XrefsDirectionArg = "to",
    depth: Annotated[int, Field(ge=1, le=5)] = 1,
    diff: bool = False,
) -> dict:
    """Trace references through a binary - find who calls a function, what a
    function depends on, or build a call graph.

    This tool answers navigation questions:
      - "Who calls malloc?" -> xrefs(binary, "malloc") - default direction="to"
      - "What does main call?" -> xrefs(binary, "main", direction="from")
      - "Show me the call tree around this function" -> xrefs(binary, "parse_input", depth=3)
      - "What changed between these two versions?" -> xrefs(binary_a, binary_b, diff=True)

    The behavior changes based on parameters:

      direction="to" (default): returns a list of references TO the target -
      every place that calls or reads from this address. Use this to find entry
      points into a function or to trace how data flows to a location.

      direction="from": returns what the target calls or references. Faster than
      decompiling when you only need the dependency list, not the code.

      depth>1: expands into a full call graph (up to depth=5). At depth=1 you
      get direct references; at depth=2+ you get transitive callers/callees.
      Use this to understand how a function fits into the broader program.

      Pass a list of targets (up to 20) for batch xref lookup - more efficient
      than repeated single calls when investigating a group of related functions.

      diff=True: compare symbol tables between binary and target (which should
      be the name of a second loaded binary). Returns added, removed, and common
      symbols. Use for patch diffing between two versions of the same binary.

    Args:
        binary: Binary name or unit_id.
        target: Function/symbol name or address, or list for batch, or binary name for diff.
        direction: Reference direction:
            - "to" (default): who calls/uses this target
            - "from": what this target calls/uses
        depth: Call graph depth (default 1, max 5). Use depth>1 for full call graph.
        diff: If True, compare symbols between binary and target (another binary name).
    """
    direction = _validate_choice("direction", direction, _XREF_DIRECTIONS)
    depth = _validate_minimum("depth", depth, 1)

    def op():
        # Symbol diff mode
        if diff:
            import heapq
            if not isinstance(target, str):
                raise ValueError("diff=True requires target to be a single binary name or unit_id")
            handle_a = _get_handle(binary)
            handle_b = _get_handle(target)

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

        handle = _get_handle(binary)
        tools = _tools_for(handle)

        # Batch xrefs
        if isinstance(target, list):
            if len(target) > _MAX_BATCH_XREF_TARGETS:
                raise ValueError(f"Max {_MAX_BATCH_XREF_TARGETS} targets per call")
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

        # Call graph (depth > 1; Field already caps depth at 5)
        if depth > 1:
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

    def _run():
        with _backend_lock:
            return _guarded_tool_call("xrefs", op)

    return await asyncio.to_thread(_run)


@mcp.tool(annotations=_read_only("Search Binary"))
async def search(
    binary: NonEmptyStr,
    query: SearchQueryArg,
    ctx: Context,
    type: SearchTypeArg = "strings",
    mode: SearchModeArg = "indexed",
    limit: Annotated[int, Field(ge=1)] = 30,
    bg: bool = False,
) -> dict:
    """Find strings, byte patterns, symbols, or search everything at once. This
    is the primary discovery tool for finding interesting targets to investigate
    with code() or xrefs().

    Default (type="strings", mode="indexed") searches Ghidra's defined string
    list - fast and returns xref information (which functions reference each
    string). Use this first. If expected strings are missing, switch to
    mode="deep" which scans raw memory for ASCII runs that Ghidra hasn't
    classified as strings yet - slower but finds strings in lightly-analyzed
    sections.

    For batch efficiency, pass a list of queries (up to 20) to search multiple
    patterns in one call - reads memory once instead of N times. Use bg=True
    to run batch searches in the background; poll results with binaries(jobs=True).

    The type parameter selects what to search:

      - "strings" (default): string references with xrefs. Pair with mode="indexed"
        (fast, defined strings) or mode="deep" (raw memory scan).

      - "symbols": search the symbol table by name. Use when looking for a
        specific named symbol rather than browsing functions.

      - "bytes": search for a hex byte pattern (e.g., "cafebabe"). Use to find
        magic numbers, crypto constants, or known byte signatures.

      - "all": search functions, symbols, and strings simultaneously. Use for
        broad exploration when you don't know whether your term is a function
        name, symbol, or embedded string.

      - "blob": extract strings from a raw memory region (query="offset,size").
        Use after info(detail="full") identifies an embedded runtime with
        strategy="search_payload" - pass the payload_offset as the offset.

      - "extract": extract embedded BunFS filesystem from Bun binaries. Always
        runs in background; poll with binaries(jobs=True).

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
    type = _validate_choice("type", type, _SEARCH_TYPES)
    mode = _validate_choice("mode", mode, _SEARCH_MODES)
    limit = _validate_minimum("limit", limit, 1)

    # Handle resolution may hot-load an evicted binary from disk -- offload it.
    # JVM work below runs through _locked_tools so it is serialized with the
    # other read tools under _backend_lock (not held during handle resolution).
    handle = await asyncio.to_thread(_get_handle, binary)

    # Batch search
    if isinstance(query, list):
        if len(query) > _MAX_BATCH_SEARCH_QUERIES:
            raise ValueError(f"Max {_MAX_BATCH_SEARCH_QUERIES} queries per call")
        if type != "strings":
            raise ValueError("Batch query lists currently support type='strings' only")
        if bg:
            _reject_if_jobs_full()
            job_id = _new_job_id()
            job: dict = {"kind": "scan", "label": "batch_search",
                         "binary": binary, "status": "queued", "job_id": job_id}
            with _jobs_mutex:
                _active_jobs[job_id] = job

            fn = lambda: _locked_tools(handle, lambda t: {"results": t.batch_search_strings(
                query, mode=mode, limit_per_query=limit,
            )})
            asyncio.create_task(_run_scan_task(job_id, job, fn))
            return {
                "job_id": job_id,
                "status": "queued",
                "hint": "Poll binaries(jobs=True); completed scan jobs include result when available.",
            }

        return await asyncio.to_thread(
            lambda: _locked_tools(handle, lambda t: {
                "queries": query,
                "results": t.batch_search_strings(query, mode=mode, limit_per_query=limit),
            })
        )

    # Single query searches
    if type != "strings" and mode != "indexed":
        raise ValueError("mode only applies to type='strings'")

    if type == "extract":
        # BunFS extraction - always background
        _reject_if_jobs_full()
        handle_analysis_id = _handle_analysis_id(handle)
        status_match = _find_on_disk(handle_analysis_id) if handle_analysis_id else None
        status = status_match or _read_status_file(getattr(handle, "unit_id", "")) or {}
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
            "hint": "Poll binaries(jobs=True); completed scan jobs include result when available.",
        }

    # Remaining single-query searches are blocking JVM work -- run off the loop,
    # serialized under _backend_lock via _locked_tools.
    def _single(tools) -> dict:
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

    return await asyncio.to_thread(lambda: _locked_tools(handle, _single))


# =============================================================================
# WRITE TOOL (opt-in, human-confirmed)
# =============================================================================
# annotate is the only tool that mutates a binary. It is OFF unless the operator
# started the server with --allow-write, and every individual change is gated
# behind an MCP elicitation prompt the human must accept. If the client cannot
# elicit, the write fails closed (preview only). This keeps the default posture
# read-only while letting an analyst-agent persist its findings under supervision.

class _ConfirmWrite(BaseModel):
    """Elicitation schema for the per-change human confirmation (primitive-only)."""
    confirm: bool = Field(default=False, description="Apply this change to the binary?")


async def _confirm_or_refuse(ctx: Context, summary: str) -> bool:
    """Ask the human to confirm a write via MCP elicitation; fail closed.

    Returns True only when the client advertises elicitation support AND the
    user explicitly accepts. A client that cannot elicit, a declined/cancelled
    prompt, or any transport error all yield False -- no write happens.
    """
    try:
        supported = ctx.session.check_client_capability(
            ClientCapabilities(elicitation=ElicitationCapability())
        )
    except Exception:
        return False
    if not supported:
        return False
    try:
        result = await ctx.elicit(message=summary, schema=_ConfirmWrite)
    except Exception:
        # McpError (client errored) or any client/transport failure -> no write.
        return False
    return getattr(result, "action", None) == "accept" and bool(
        getattr(getattr(result, "data", None), "confirm", False)
    )


def _annotate_summary(action: str, preview: dict, new_value: str) -> str:
    """Human-readable description of the pending change for the confirm prompt."""
    target = preview.get("target")
    addr = preview.get("target_addr")
    old = preview.get("old", "")
    if action == "rename":
        return f"Rename function {old} -> {new_value} (at {addr})?"
    if action == "comment":
        return f"Set comment on {target} (at {addr}):\n{new_value}"
    return f"Apply prototype to {target} (at {addr}):\n  was: {old}\n  new: {new_value}"


def _apply_prototype(prog, func, signature_text: str) -> None:
    """Parse a C prototype and apply it to func within the caller's transaction."""
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import TaskMonitor

    parser = FunctionSignatureParser(prog.getDataTypeManager(), None)
    try:
        sig = parser.parse(func.getSignature(), signature_text)
    except Exception as exc:
        raise ValueError(f"could not parse prototype: {_sanitize_error_text(str(exc))}") from exc
    if sig is None:
        raise ValueError("could not parse prototype")
    cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED)
    if not cmd.applyTo(prog, TaskMonitor.DUMMY):
        raise ValueError(f"failed to apply prototype: {cmd.getStatusMsg()}")


# --- write audit journal + volume warning ------------------------------------
# MCP elicitation can't stop an auto-approving client from self-confirming, so
# every write -- and every declined/failed attempt -- is appended to a JSONL
# journal next to the on-disk projects. Each entry records old -> new, so the
# journal doubles as an undo log; a flood of entries is the signal that an
# auto-agent is churning. A per-session counter also nudges via ctx.warning.

_audit_lock = threading.Lock()
# Write-attempt counters, genuinely per client session: a shared HTTP/SSE server
# serves many sessions from one process, so a module-global counter would leak
# one client's volume into another's warnings. Keyed weakly so entries vanish
# when a session ends; falls back to a global only if no usable session exists.
_write_attempts_by_session: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_annotate_attempts = 0  # fallback counter (stdio/no-session)
_ANNOTATE_WARN_EVERY = 25  # nudge every N write attempts in a session
_AUDIT_MAX_BYTES = 5 * 1024 * 1024  # rotate the journal past this size
_AUDIT_MAX_BACKUPS = 5  # keep this many rotated journals (bounds disk use)
_AUDIT_FILENAME = "annotate_audit.jsonl"


def _audit_log_path() -> Path:
    """Location of the append-only annotate audit journal."""
    try:
        base = get_backend().project_dir
    except Exception:
        base = get_config().project_dir or DEFAULT_PROJECT_DIR
    return Path(base) / _AUDIT_FILENAME


def _rotate_audit_if_needed(path: Path) -> None:
    """Size-based rotation so the journal can't grow without bound. Best-effort:
    rotation problems must never block a write. Held under _audit_lock."""
    try:
        if not path.exists() or path.stat().st_size < _AUDIT_MAX_BYTES:
            return
        # Shift .(N-1) -> .N, ..., .1 -> .2, then current -> .1. The oldest is
        # dropped, so disk use is bounded at ~(_AUDIT_MAX_BACKUPS + 1) * max size.
        for i in range(_AUDIT_MAX_BACKUPS - 1, 0, -1):
            src = path.with_name(f"{path.name}.{i}")
            if src.exists():
                os.replace(src, path.with_name(f"{path.name}.{i + 1}"))
        os.replace(path, path.with_name(f"{path.name}.1"))
    except OSError as exc:
        logger.warning("annotate audit log rotation skipped: %s", exc)


def _audit_append(record: dict) -> None:
    """Append one JSON line to the journal, hardened. Raises on any failure so
    callers can choose to fail closed.

    - O_NOFOLLOW refuses a symlinked journal path (an attacker can't redirect the
      audit trail to clobber another file).
    - 0o600 keeps the trail owner-only.
    - json.dumps escapes control chars, so a malicious old/new/comment value
      cannot forge extra lines via embedded newlines.
    """
    path = _audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, separators=(",", ":"), default=str)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):  # POSIX only; harmless to omit on Windows
        flags |= os.O_NOFOLLOW
    with _audit_lock:
        _rotate_audit_if_needed(path)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def _audit_write(preview: dict, outcome: str, detail: str = "", *, required: bool = False) -> None:
    """Record one annotate outcome in the audit journal.

    With required=True the call fails closed: if the entry can't be durably
    written, an McpError is raised so the caller can refuse the write rather than
    apply an unrecorded change. With required=False (declined/compensating notes,
    where nothing irreversible happened) failures are swallowed and only logged.
    """
    from datetime import UTC, datetime

    record = {
        "ts": datetime.now(UTC).isoformat(),
        "binary": preview.get("binary"),
        "unit_id": preview.get("unit_id"),
        "analysis_id": preview.get("analysis_id"),
        "action": preview.get("action"),
        "target": preview.get("target"),
        "addr": preview.get("target_addr"),
        "old": preview.get("old"),
        "new": preview.get("new"),
        "outcome": outcome,
    }
    if detail:
        record["detail"] = _sanitize_error_text(detail)
    try:
        _audit_append(record)
        logger.info("annotate %s: %s %r -> %r on %s",
                    outcome, record["action"], record["old"], record["new"], record["binary"])
    except Exception as exc:
        logger.warning("annotate audit log write failed: %s", exc)
        if required:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=(
                    "Write aborted: the change could not be recorded in the audit journal, "
                    "and this server records every write before applying it. Ensure the "
                    "project directory is writable and the journal is not a symlink "
                    f"({_AUDIT_FILENAME})."
                ),
            )) from exc


def _bump_write_attempts(ctx: Context) -> int:
    """Increment and return this session's write-attempt count.

    Per-session via a weak-keyed map on ctx.session; if no session is usable as
    a weak key, fall back to a process-global counter so the nudge still fires.
    """
    global _annotate_attempts
    session = getattr(ctx, "session", None)
    if session is not None:
        try:
            n = _write_attempts_by_session.get(session, 0) + 1
            _write_attempts_by_session[session] = n
            return n
        except TypeError:
            pass  # session not weak-referenceable/hashable -> global fallback
    _annotate_attempts += 1
    return _annotate_attempts


async def _note_write_volume(ctx: Context, binary: str) -> None:
    """Increment the session write-attempt counter; nudge on threshold crossings."""
    n = _bump_write_attempts(ctx)
    if n % _ANNOTATE_WARN_EVERY == 0:
        with suppress(Exception):
            # Only the journal's filename is sent to the client -- the full path
            # is server-side detail (logged locally), not for remote disclosure.
            await ctx.warning(
                f"annotate has been called {n} times this session (latest target on "
                f"{binary}). All writes are recorded in the audit journal "
                f"({_AUDIT_FILENAME})."
            )


@mcp.tool(annotations=_write_annotation("Annotate Binary"))
async def annotate(
    binary: NonEmptyStr,
    target: NonEmptyStr,
    action: AnnotateActionArg,
    ctx: Context,
    name: str = "",
    comment: str = "",
    prototype: str = "",
) -> dict:
    """Persist an analysis finding back into the binary: rename a function, set a
    comment, or apply a corrected prototype. **This is the only tool that writes.**

    Writes are opt-in and human-supervised:

      - The server must be started with `--allow-write`; otherwise every call is
        refused (the default posture is strictly read-only).
      - Each change requires interactive confirmation: the server elicits a
        yes/no from you (the human) showing the exact old -> new before it
        commits. If your client can't show that prompt, the call returns a
        preview with applied=false and writes nothing (fail closed).
      - Every write is recorded in an audit journal next to the projects
        *before* it is applied (fail closed: if the change can't be journaled,
        it isn't committed), and declined/failed attempts are logged too. Each
        entry records old -> new, so changes stay accountable and reversible
        even under an auto-approving client.

    The action parameter selects what to write:

      - "rename": give a function a meaningful name. Pass name=. Reversible.
      - "comment": attach a plate comment to a function. Pass comment=.
      - "prototype": apply a C function signature (e.g. "int parse(char *buf, int len)").
        Pass prototype=. Updates parameter types and return type.

    Args:
        binary: Binary name or unit_id.
        target: Function name or 0x-address to annotate.
        action: "rename", "comment", or "prototype".
        name: New function name (action="rename").
        comment: Comment text (action="comment").
        prototype: C signature (action="prototype").

    Returns:
        {binary, target, action, old, new, applied, reason?}. applied is False
        (with a reason) when the change was not confirmed.
    """
    # 1) Gate: writes are opt-in. This must be the first thing the tool does so a
    #    read-only server never resolves a handle or builds a preview for a write.
    if not get_config().allow_write:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=(
                "Write operations are disabled: the server is running read-only. "
                "Restart with `pyghidra-lite serve --allow-write` and reconnect to "
                "enable annotate (rename/comment/prototype)."
            ),
        ))

    action = _validate_choice("action", action, _ANNOTATE_ACTIONS)

    # 2) Per-action validation; new_value is exactly what we will write.
    if action == "rename":
        new_value = _validate_symbol_name(name)
    elif action == "comment":
        if not comment.strip():
            raise McpError(ErrorData(code=INVALID_PARAMS, message="comment must be non-empty"))
        new_value = comment
    else:  # prototype
        if not prototype.strip():
            raise McpError(ErrorData(code=INVALID_PARAMS, message="prototype must be non-empty"))
        new_value = prototype.strip()

    # 3) Preview (read-only): resolve the function and capture the current value
    #    so the human sees the exact old -> new and so commit can detect drift.
    def _preview_op(handle):
        tools = _tools_for(handle)
        func = tools._find_function(target)
        if func is None:
            raise ValueError(f"Function not found: {target}")
        if action == "rename":
            old = func.getName()
        elif action == "comment":
            old = func.getComment() or ""
        else:
            try:
                old = str(func.getSignature().getPrototypeString())
            except Exception:
                old = str(func.getSignature())
        return {
            "binary": handle.name,
            "unit_id": getattr(handle, "unit_id", None),
            "analysis_id": getattr(handle, "analysis_id", None),
            "target": target,
            "target_addr": str(func.getEntryPoint()),
            "action": action,
            "old": old,
            "new": new_value,
        }

    preview = await _with_handle_async("annotate", binary, _preview_op)

    # Count the attempt and nudge if write volume is high this session. Elicitation
    # can't stop an auto-approving client, so a flood of writes should be loud.
    await _note_write_volume(ctx, binary)

    # 4) Human-in-the-loop confirmation. Fail closed on decline/cancel/unsupported.
    if not await _confirm_or_refuse(ctx, _annotate_summary(action, preview, new_value)):
        _audit_write(preview, "declined")
        return {
            **preview,
            "applied": False,
            "reason": "change not confirmed (elicitation declined, cancelled, or unsupported)",
        }

    # 5) Commit under the backend lock: re-resolve and re-verify the target hasn't
    #    moved since the preview, then write in a single transaction and persist.
    def _commit_op(handle):
        tools = _tools_for(handle)
        func = tools._find_function(target)
        if func is None:
            raise ValueError(f"Function not found: {target}")
        if str(func.getEntryPoint()) != preview["target_addr"]:
            raise ValueError("binary changed since preview; aborting write")
        from ghidra.program.model.symbol import SourceType
        prog = handle.program
        tx_id = prog.startTransaction(f"annotate:{action}")
        success = False
        try:
            if action == "rename":
                func.setName(new_value, SourceType.USER_DEFINED)
            elif action == "comment":
                func.setComment(new_value or None)
            else:
                _apply_prototype(prog, func, new_value)
            success = True
        finally:
            prog.endTransaction(tx_id, success)
        get_backend().save_program(handle)
        tools.invalidate_cache()
        return {
            "binary": handle.name,
            "target": target,
            "action": action,
            "old": preview["old"],
            "new": new_value,
            "applied": True,
        }

    # Fail-closed audit: durably record the intended write BEFORE committing, so a
    # committed change can never go unrecorded. If the journal can't be written
    # this raises and nothing is committed; a rare commit failure afterwards gets
    # a best-effort compensating "failed" note.
    _audit_write(preview, "applied", required=True)
    try:
        return await _with_handle_async("annotate", binary, _commit_op)
    except Exception as exc:
        _audit_write(preview, "failed", detail=str(exc))
        raise


# =============================================================================
# LEGACY TOOL ALIASES (hidden from model, route to consolidated tools)
# =============================================================================

# The old tool names have been consolidated into the 8 public tools above.
# Keep comments here in sync with the actual server implementation.


# =============================================================================
# REMOVED: Old tool registrations
# =============================================================================
# The following tools have been consolidated:
# - import_binary, analyze_binary, reanalyze -> load
# - delete_binary, cancel_analysis -> delete
# - list_binaries, analysis_status, get_job_result -> binaries
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

def _kill_job(analysis_id: str) -> None:
    """Kill any active worker for analysis_id and remove it from _active_jobs."""
    with _jobs_mutex:
        job = _active_jobs.pop(analysis_id, None)
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
    # Only the runtime detection touches the JVM -- serialize that under the
    # backend lock; the bun subprocess below runs unlocked (it can take minutes).
    rt_info = _locked_tools(handle, lambda t: t.detect_embedded_runtime(compact=False))
    bun_rt = next((r for r in rt_info.get("runtimes", []) if r["type"] == "bunfs"), None)
    if not bun_rt:
        raise ValueError("No bunfs payload detected.")

    handle_analysis_id = _handle_analysis_id(handle)
    status_match = _find_on_disk(handle_analysis_id) if handle_analysis_id else None
    status = status_match or _read_status_file(getattr(handle, "unit_id", "")) or {}
    binary_path_str = status.get("binary_path")
    if not binary_path_str:
        raise ValueError("binary_path not recorded in status file.")
    binary_path = Path(binary_path_str)
    if not binary_path.exists():
        raise FileNotFoundError("Original binary no longer exists on disk.")

    out.mkdir(parents=True, exist_ok=True)
    strategy_used = None

    # Invoke a locally pre-installed, pinned extractor DIRECTLY. The previous
    # implementation ran `bun x bun-extract-bundled`, which resolves and executes
    # an npm package from the network on every call -- i.e. a tool call could
    # fetch and run arbitrary remote code. We removed that: the only thing we run
    # here is an extractor the operator has already installed on PATH, with a
    # fixed argument vector (no shell, no package-manager launcher).
    extractor = shutil.which("bun-extract-bundled")
    if extractor:
        try:
            result = subprocess.run(
                [extractor, str(binary_path), str(out)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                strategy_used = "bun-extract-bundled"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    if strategy_used is None:
        raise RuntimeError(
            "bunfs extraction unavailable. Install the 'bun-extract-bundled' "
            "executable on PATH (e.g. `bun add -g bun-extract-bundled`); "
            "pyghidra-lite no longer fetches it from the network at run time."
        )

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


def _is_loopback_host(host: str) -> bool:
    """True when host is a loopback bind that is not externally reachable.

    Accepts the literal "localhost" and any loopback IP (127.0.0.0/8, ::1),
    including the bracketed IPv6 form "[::1]". Non-loopback hosts and the
    wildcard binds (0.0.0.0, ::) return False, so the caller can require auth.
    The old guard compared against the literal "127.0.0.1" only, which let
    127.0.0.2, ::1, hostnames, and ::-wildcard slip through.
    """
    h = host.strip().lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h.strip("[]")).is_loopback
    except ValueError:
        return False


def _build_transport_security(
    host: str, port: int, extra_hosts: tuple[str, ...] = ()
) -> TransportSecuritySettings:
    """Build DNS-rebinding protection settings for an HTTP/SSE bind.

    The MCP transport-security guidance calls for validating the Host and Origin
    headers so a malicious web page can't rebind DNS to the local server. We
    always allow localhost variants plus the configured bind host; operators
    fronting the server under another hostname add it via --allowed-host.
    """
    hostnames = {"localhost", "127.0.0.1", "::1", "[::1]"}
    if host and host not in ("0.0.0.0", "::"):
        hostnames.add(host)

    allowed_hosts: set[str] = set()
    allowed_origins: set[str] = set()
    for hn in hostnames:
        allowed_hosts.add(f"{hn}:{port}")
        allowed_hosts.add(f"{hn}:*")
        allowed_origins.add(f"http://{hn}:{port}")
        allowed_origins.add(f"https://{hn}:{port}")

    for entry in extra_hosts:
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            entry = f"{entry}:*"
        allowed_hosts.add(entry)
        if not entry.endswith(":*"):
            allowed_origins.add(f"http://{entry}")
            allowed_origins.add(f"https://{entry}")

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sorted(allowed_hosts),
        allowed_origins=sorted(allowed_origins),
    )


class _BearerAuthMiddleware:
    """ASGI middleware enforcing a static bearer token on every HTTP request.

    The MCP server itself has no auth; for non-loopback binds a shared token is
    the minimum bar so that merely reaching the port is not enough to call every
    tool (including delete). Compared in constant time to avoid timing oracles.
    Non-HTTP scopes (lifespan) pass through untouched.
    """

    def __init__(self, app, token: str):
        self.app = app
        self._expected = f"Bearer {token}"

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        provided = headers.get(b"authorization", b"").decode("latin-1")
        if not secrets.compare_digest(provided, self._expected):
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b"Bearer"),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error":"unauthorized"}',
            })
            return
        return await self.app(scope, receive, send)


class _IdleTracker:
    """ASGI middleware that records the time of the last HTTP request."""

    def __init__(self, app):
        self.app = app
        self.last_request = time.time()
        self._lock = threading.Lock()

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            with self._lock:
                self.last_request = time.time()
        return await self.app(scope, receive, send)

    def idle_seconds(self) -> float:
        with self._lock:
            return time.time() - self.last_request


def _serve_http(
    mcp_server,
    *,
    transport: str,
    auth_token: str | None = None,
    idle_minutes: int | None = None,
) -> None:
    """Serve an HTTP/SSE MCP app via uvicorn with optional auth + idle exit.

    Replaces the bare mcp.run() for the HTTP family so a single path applies the
    bearer-auth and idle-timeout middleware (DNS-rebinding protection is wired
    in earlier via mcp.settings.transport_security).
    """
    import uvicorn

    app = mcp_server.sse_app() if transport == "sse" else mcp_server.streamable_http_app()
    if auth_token:
        app = _BearerAuthMiddleware(app, auth_token)

    idle = None
    if idle_minutes and idle_minutes > 0:
        idle = _IdleTracker(app)
        app = idle

    config = uvicorn.Config(
        app,
        host=mcp_server.settings.host,
        port=mcp_server.settings.port,
        log_level=mcp_server.settings.log_level.lower(),
        limit_concurrency=20,
        limit_max_requests=10000,
        timeout_keep_alive=30,
        h11_max_incomplete_event_size=1024 * 1024,
    )
    server = uvicorn.Server(config)

    if idle is not None:
        def watchdog(srv: uvicorn.Server, tracker: _IdleTracker):
            timeout_sec = idle_minutes * 60
            while not srv.started:
                time.sleep(0.1)
            while srv.started:
                time.sleep(30)
                if tracker.idle_seconds() >= timeout_sec:
                    logger.info("Idle for %d minutes, shutting down.", idle_minutes)
                    srv.should_exit = True
                    return

        threading.Thread(target=watchdog, args=(server, idle), daemon=True).start()

    # anyio.run is used by FastMCP internally; replicate here
    import anyio
    anyio.run(server.serve)

class DefaultGroup(click.Group):
    """Routes bare invocations to the 'proxy' subcommand (lightweight auto-start)."""

    _group_flags = frozenset({"-v", "--version", "--help", "-h"})

    def parse_args(self, ctx, args):
        if not args:
            args = ["proxy"]
        elif args[0] not in self.commands and args[0] not in self._group_flags:
            # Backward compat: unknown args (e.g. --transport, binary paths)
            # route to serve
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
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
    help="Transport: stdio (per-session), sse (legacy), or streamable-http (shared HTTP)",
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
    "--restrict-path",
    "restrict_paths",
    type=click.Path(path_type=Path),
    multiple=True,
    help="Restrict imports to these paths only (repeatable). Unrestricted by default.",
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
@click.option(
    "--evict-after", type=int, default=None,
    help="Unload binaries from memory after this many idle minutes (default 30, 0 = off). "
         "Evicted binaries stay on disk and reload transparently on next access.",
)
@click.option(
    "--min-loaded", type=int, default=None,
    help="Always keep at least this many most-recently-used binaries in memory (default 2).",
)
@click.option(
    "--allow-write/--no-allow-write", default=False, envvar="PYGHIDRA_LITE_ALLOW_WRITE",
    help="Enable the annotate write tool (rename/comment/prototype). Off by default "
         "(read-only). Each write still requires interactive confirmation from the "
         "user via MCP elicitation; clients that can't confirm get a preview only.",
)
@click.option(
    "--idle-timeout", type=int, default=None,
    help="Auto-exit after this many minutes with no HTTP requests (shared mode only). "
         "Set by proxy auto-start; 0 or None disables.",
)
@click.option(
    "--auth-token", type=str, default=None, envvar="PYGHIDRA_LITE_AUTH_TOKEN",
    help="Require this bearer token on every HTTP/SSE request (shared mode). "
         "Required for non-loopback binds. Reads PYGHIDRA_LITE_AUTH_TOKEN.",
)
@click.option(
    "--allowed-host", "allowed_hosts", type=str, multiple=True,
    help="Extra Host header value to accept for DNS-rebinding protection "
         "(host:port or host:*). Repeatable. Add this when fronting the server "
         "under a hostname other than the bind address.",
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
    restrict_paths: tuple[Path, ...],
    max_workers: int,
    eager_load: bool,
    autopurge_days: int | None,
    evict_after: int | None,
    min_loaded: int | None,
    allow_write: bool,
    idle_timeout: int | None,
    auth_token: str | None,
    allowed_hosts: tuple[str, ...],
    binaries: tuple[Path, ...],
):
    """Start the MCP server (default when no subcommand given)."""
    global _backend, _worker_semaphore, _active_jobs_lock

    is_shared = transport != "stdio"

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
        restrict_paths=list(restrict_paths),
        shared=is_shared,
        autopurge_days=autopurge_days,
        evict_after_minutes=evict_after,
        min_loaded=min_loaded,
        allow_write=allow_write,
    )
    is_loopback = _is_loopback_host(host)
    if is_shared and not is_loopback:
        if not restrict_paths:
            logger.error(
                "--restrict-path is required when binding to a non-loopback address (%s).",
                host,
            )
            raise SystemExit(1)
        if not auth_token:
            logger.error(
                "--auth-token (or PYGHIDRA_LITE_AUTH_TOKEN) is required when binding to a "
                "non-loopback address (%s): the server has no other access control, so any "
                "host that can reach the port could call every tool, including delete.",
                host,
            )
            raise SystemExit(1)
    if is_shared and not restrict_paths:
        logger.warning(
            "Shared mode with no --restrict-path. "
            "Set --restrict-path for production deployments."
        )
    # Resolve runtime_home now and persist it into the (still pre-live) config so
    # error redaction and the import worker see the same resolved path. This must
    # happen before go_live(), the last point at which config can change.
    resolved_home = _ensure_runtime_environment(get_config().project_dir, get_config().runtime_home)
    configure_server(runtime_home=resolved_home)
    _check_prerequisites(ghidra_dir)
    with _backend_lock:
        _backend = _init_backend(eager_load=eager_load)

    if allow_write:
        logger.info(
            "Write tools enabled (annotate); each change requires user confirmation. "
            "Audit journal: %s", _audit_log_path(),
        )

    # Detect capabilities for all pre-loaded binaries
    for prog_name in _backend.list_programs():
        handle = _backend.get_program(prog_name)
        _ensure_capabilities(handle)
        logger.info(
            "Pre-loaded %s (unit_id=%s, analysis_id=%s, analyzed=%s)",
            handle.name,
            handle.unit_id,
            handle.analysis_id,
            handle.analyzed,
        )

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

    # Write PID file for shared transports so `pyghidra-lite stop` works
    if transport in ("streamable-http", "sse"):
        from pyghidra_lite.proxy import _write_pid, _remove_pid
        _write_pid(port, os.getpid())

    # Set the HTTP security holders ONCE, then assert DNS-rebinding protection is
    # actually active before serving -- fail closed rather than expose an
    # unprotected endpoint. These are the last writes before the config lock.
    if transport != "stdio":
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.settings.transport_security = _build_transport_security(host, port, allowed_hosts)
        ts = mcp.settings.transport_security
        if ts is None or not ts.enable_dns_rebinding_protection:
            raise SystemExit("refusing to serve HTTP without DNS-rebinding protection enabled")
        if auth_token:
            logger.info("Bearer token auth enabled for %s transport.", transport)

    # Lock configuration for the lifetime of the process. From here, no in-process
    # path can change a security setting; to change one, stop and re-run the CLI.
    go_live()

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        else:
            _serve_http(
                mcp,
                transport=transport,
                auth_token=auth_token,
                idle_minutes=idle_timeout,
            )
    finally:
        if transport in ("streamable-http", "sse"):
            _remove_pid(port)
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
@click.option(
    "--bootstrap-mode",
    type=click.Choice(sorted(_BOOTSTRAP_MODES)),
    default="named",
    show_default=True,
    help="Bootstrap transfer mode: semantic names only, or all functions with synthetic labels.",
)
def import_cmd(
    binaries,
    profile,
    ghidra_dir,
    project_dir,
    runtime_home,
    jvm_heap,
    bootstrap,
    bootstrap_mode,
):
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
        analysis_id = make_analysis_id(unit_id, profile_enum)
        project_dir_path = Path(project_dir) / analysis_id

        status_path = project_dir_path / ".analysis_status"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        listener = AnalysisProgressListener(
            status_path, path.name, profile, path.stat().st_size,
            unit_id=unit_id,
            analysis_id=analysis_id,
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
            bootstrap_meta = None
            if bootstrap:
                current_phase = "bootstrap"
                bootstrap_stats = _apply_bootstrap_transfer(
                    backend,
                    bootstrap,
                    handle,
                    mode=bootstrap_mode,
                )
                source_handle = _resolve_bootstrap_handle(backend, bootstrap)
                bootstrap_meta = _bootstrap_meta(
                    source_handle.analysis_id,
                    bootstrap_stats,
                    mode=bootstrap_mode,
                )

            caps = detect_capabilities(handle)
            cap_list = _format_capabilities(caps)

            func_count = handle.program.getFunctionManager().getFunctionCount()
            if not handle.was_preexisting:
                listener.complete(func_count, cap_list, bootstrap=bootstrap_meta)

            if handle.was_preexisting:
                click.echo(f"  {path.name}: already analyzed "
                           f"(unit_id={unit_id}, analysis_id={handle.analysis_id}, {func_count} functions)")
            else:
                message = (f"  {path.name}: {func_count} functions, "
                           f"[{', '.join(cap_list) or 'generic'}] "
                           f"(unit_id={unit_id}, analysis_id={handle.analysis_id}, profile={profile})")
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
        try:
            _validate_project_id(entry.name)
        except ValueError:
            continue
        gpr_files = list(entry.glob("*.gpr"))
        if not gpr_files:
            continue

        size = sum(f.stat().st_size for f in entry.rglob("*") if f.is_file())
        status_file = entry / ".analysis_status"

        status_data = {}
        try:
            fd = os.open(str(status_file), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            pass
        else:
            try:
                with os.fdopen(fd, "r") as f:
                    status_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                status_data = {}

        info = {
            "project_id": entry.name,
            "unit_id": status_data.get("unit_id") or (parse_analysis_id(entry.name)[0] if parse_analysis_id(entry.name) else entry.name),
            "analysis_id": status_data.get("analysis_id") or (entry.name if parse_analysis_id(entry.name) else make_analysis_id(entry.name, status_data.get("profile", AnalysisProfile.FAST.value))),
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
            click.echo(
                f"  {e['analysis_id']}  {e['size_mb']:>6.1f}MB  "
                f"[{e['status']}]  {e['binary_name']}  {funcs}  {caps}"
            )


@cli.command("proxy")
@click.option("-p", "--port", type=int, default=19101,
              help="Backend port (default 19101)")
@click.option("--host", type=str, default="127.0.0.1",
              help="Backend host")
def proxy_cmd(port: int, host: str):
    """Lightweight stdio proxy to a shared HTTP backend.

    Reads MCP JSON-RPC from stdin, forwards to the persistent backend over HTTP,
    and writes responses to stdout. Auto-starts the backend if it's not running.
    """
    import anyio
    from functools import partial
    from pyghidra_lite.proxy import run_proxy
    anyio.run(partial(run_proxy, host=host, port=port))


@cli.command("stop")
@click.option("-p", "--port", type=int, default=19101,
              help="Backend port (default 19101)")
def stop_cmd(port: int):
    """Stop a running backend process."""
    from pyghidra_lite.proxy import stop_backend
    if stop_backend(port):
        click.echo(f"Backend on port {port} stopped.")
    else:
        click.echo(f"No backend found on port {port}.", err=True)
        raise SystemExit(1)


class AnalysisProgressListener:
    """Writes analysis progress to a JSON status file for subprocess worker consumption."""

    def __init__(self, status_path: Path, binary_name: str,
                 profile: str, binary_size: int,
                 unit_id: str | None = None,
                 analysis_id: str | None = None,
                 binary_path: str | None = None):
        self.status_path = status_path
        self.binary_name = binary_name
        self.binary_path = binary_path
        self.profile = profile
        self.binary_size = binary_size
        self.unit_id = unit_id
        self.analysis_id = analysis_id
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
        if self.unit_id:
            data["unit_id"] = self.unit_id
        if self.analysis_id:
            data["analysis_id"] = self.analysis_id
        if self.binary_path:
            data["binary_path"] = self.binary_path
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=None))
        tmp.rename(self.status_path)


def main():
    """Entry point for pyproject.toml console_scripts."""
    cli()


def proxy_main():
    """Entry point for pyghidra-lite-proxy console script."""
    cli.main(["proxy"], standalone_mode=True)


if __name__ == "__main__":
    main()


# =============================================================================
# OLD TOOLS REMOVED - DO NOT ADD BELOW THIS LINE
# =============================================================================
# All 58 original tools have been consolidated into 8 tools above:
#   load, delete, binaries, info, functions, code, xrefs, search

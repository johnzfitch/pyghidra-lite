"""pyghidra-lite MCP server - capability-based toolset with auto-detection."""

import asyncio
import logging
import os
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
from pyghidra_lite.backend import GhidraBackend
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


@dataclass
class ServerConfig:
    """Configuration for backend initialization and import policy."""
    project_name: str = "pyghidra_lite"
    project_dir: Path | None = None
    default_profile: AnalysisProfile = AnalysisProfile.FAST
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


def _load_config_from_env() -> ServerConfig:
    config = ServerConfig()
    if project_name := os.getenv("PYGHIDRA_LITE_PROJECT_NAME"):
        config.project_name = project_name
    if project_dir := os.getenv("PYGHIDRA_LITE_PROJECT_DIR"):
        config.project_dir = Path(project_dir)
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


def _init_backend() -> GhidraBackend:
    """Initialize the backend if needed."""
    global _backend
    if _backend is None:
        config = _server_config
        _backend = GhidraBackend(
            project_name=config.project_name,
            project_dir=config.project_dir,
            default_profile=config.default_profile,
            shared=config.shared,
        )
        _backend.start()
    return _backend


def _resolve_import_path(path: str) -> Path:
    """Resolve and enforce allowlist policy for imports."""
    resolved = Path(path).expanduser().resolve()
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
    raise ValueError(f"Path not allowed: {resolved}. Allowed: {roots}")


def _get_handle(binary: str):
    backend = get_backend()
    return backend.get_program(binary)


def _ensure_capabilities(handle) -> BinaryCapabilities:
    with _backend_lock:
        caps = _capabilities.get(handle.name)
        if not caps:
            caps = detect_capabilities(handle)
            _capabilities[handle.name] = caps
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
    """Get capabilities for a binary."""
    with _backend_lock:
        if binary in _capabilities:
            return _capabilities[binary]

        # Try partial match
        matches = [k for k in _capabilities if binary in k]
        if len(matches) == 1:
            return _capabilities[matches[0]]
        if matches:
            raise ValueError(f"Ambiguous binary '{binary}'. Matches: {matches}")

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
    try:
        yield
    finally:
        with _backend_lock:
            if _backend:
                _backend.close()
                _backend = None
            _capabilities.clear()


mcp = FastMCP("pyghidra-lite", lifespan=server_lifespan)


# =============================================================================
# CORE TOOLS (Always available)
# =============================================================================

def _do_import_blocking(
    p: Path,
    profile_enum: AnalysisProfile,
    analyze: bool,
    tracker: ProgressTracker,
) -> tuple:
    """Blocking import operation (runs in thread pool)."""
    tracker.update(10, "Loading file")

    with _backend_lock:
        backend = get_backend()
        tracker.update(20, "Importing to Ghidra")

        # Import without analysis first so we can report progress
        handle = backend.import_binary(p, profile_enum, analyze=False)
        tracker.update(40, "Import complete")

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
    """Import a binary for analysis. Returns capabilities detected.

    Args:
        path: Path to binary file.
        profile: Analysis depth - "fast" (default), "default", or "deep".
        analyze: Run analysis (set False for large binaries to avoid timeout).
        list_tools: Include available_tools list (default False, saves tokens).

    Returns:
        Binary info with detected capabilities (swift, objc, macho, etc.)
        Use capability-specific tools based on what's detected.
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
            "analyzed": handle.analyzed,
            "capabilities": {
                "macho": caps.is_macho,
                "elf": caps.is_elf,
                "pe": caps.is_pe,
                "swift": caps.has_swift,
                "objc": caps.has_objc,
                "hermes": caps.has_hermes,
                "swift_module": caps.swift_module,
            },
        }

        # Only include tool list if requested (saves tokens)
        if list_tools:
            result["available_tools"] = _available_tools(caps)

        return result
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Import failed: {e}")) from e


@mcp.tool()
def list_binaries(ctx: Context, list_tools: bool = False) -> list[dict]:
    """List all loaded binaries with their capabilities.

    Args:
        list_tools: Include available_tools list per binary (default False, saves tokens).
    """
    def op():
        backend = get_backend()
        results = []
        for name in backend.list_programs():
            handle = backend.get_program(name)
            caps = _ensure_capabilities(handle)
            result = {
                "name": handle.name,
                "unit_id": handle.unit_id,
                "analyzed": handle.analyzed,
                "capabilities": {
                    "macho": caps.is_macho,
                    "elf": caps.is_elf,
                    "pe": caps.is_pe,
                    "swift": caps.has_swift,
                    "objc": caps.has_objc,
                    "hermes": caps.has_hermes,
                    "swift_module": caps.swift_module,
                },
            }
            if list_tools:
                result["available_tools"] = _available_tools(caps)
            results.append(result)
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
        if handle.name in _capabilities:
            del _capabilities[handle.name]
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
        _capabilities[handle.name] = caps

        result = {
            "name": handle.name,
            "analyzed": True,
            "profile": profile,
            "capabilities": {
                "macho": caps.is_macho,
                "elf": caps.is_elf,
                "pe": caps.is_pe,
                "swift": caps.has_swift,
                "objc": caps.has_objc,
                "hermes": caps.has_hermes,
                "swift_module": caps.swift_module,
            },
        }
        if list_tools:
            result["available_tools"] = _available_tools(caps)
        return result

    with _backend_lock:
        return _guarded_tool_call("reanalyze", op)


# =============================================================================
# CLI
# =============================================================================

@click.command()
@click.version_option(__version__, "-v", "--version")
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
@click.argument("binaries", nargs=-1, type=click.Path(exists=True, path_type=Path))
def main(
    transport: str,
    port: int,
    host: str,
    profile: str,
    project_name: str,
    project_dir: Path | None,
    allow_paths: tuple[Path, ...],
    allow_any_path: bool,
    binaries: tuple[Path, ...],
):
    """pyghidra-lite: Lightweight RE MCP server with capability detection."""
    global _backend

    if transport != "stdio":
        raise click.ClickException("SSE transport is disabled. Use --transport stdio.")

    logger.info(f"pyghidra-lite v{__version__} (profile={profile}, transport={transport})")

    profile_enum = AnalysisProfile(profile)
    # Always use shared mode - per-binary projects provide sufficient isolation
    # Analysis persists across agent suspend/resume cycles
    configure_server(
        project_name=project_name,
        project_dir=project_dir,
        default_profile=profile_enum,
        allow_any_path=allow_any_path,
        allowed_paths=list(allow_paths),
        shared=True,
    )
    with _backend_lock:
        _backend = _init_backend()

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


if __name__ == "__main__":
    main()

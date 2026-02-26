"""pyghidra-lite MCP server - import-only surgical RE toolset."""

import asyncio
import logging
import os
import shlex
import shutil
import subprocess
import sys
import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import re

import click
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_lite import __version__

from pyghidra_lite.backend import (
    DEFAULT_PROJECT_DIR,
    GhidraBackend,
    find_ghidra_install,
)
from pyghidra_lite.models import (
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


def _check_prerequisites(ghidra_dir: str | None) -> None:
    """Verify Java 21+ and Ghidra are available before starting the backend."""
    java_path = shutil.which("java")
    if not java_path:
        raise click.ClickException(
            "Java not found. Ghidra requires JDK 21+. "
            "Install: brew install openjdk@21 (macOS) / apt install openjdk-21-jdk (Ubuntu)"
        )

    try:
        result = subprocess.run(
            ["java", "-version"], capture_output=True, text=True, timeout=10
        )
        version_output = result.stderr + result.stdout
    except Exception as exc:
        raise click.ClickException(f"Failed to run 'java -version': {exc}")

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

        # Import-only workload needs modest heap (no analyzeAll)
        _upsert_jvm_option("_JAVA_OPTIONS", "-Xmx", "-Xmx512m")

        _backend = GhidraBackend(
            project_name=config.project_name,
            project_dir=config.project_dir,
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
        "binary_info",
        "list_functions",
        "disassemble",
        "decompile",
        "search_strings",
        "search_symbols",
        "list_imports",
        "list_exports",
        "get_xrefs",
        "read_bytes",
        "read_string",
        "memory_map",
        "find_bytes",
        "entropy_map",
    ]

    if caps.is_elf:
        tools.extend(["elf_info", "elf_sections", "elf_symbols", "elf_got_plt"])
    if caps.is_macho:
        tools.extend(["macho_info", "macho_segments", "macho_dylibs"])
    if caps.has_swift:
        tools.extend(["swift_info", "demangle"])
    if caps.has_objc:
        tools.append("objc_info")
    if caps.has_hermes:
        tools.append("hermes_info")

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
        if binary in _capabilities:
            return _capabilities[binary]
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

    fmt = handle.metadata.get("Executable Format", "").lower()
    if "mach-o" in fmt or "mac os" in fmt:
        caps.is_macho = True
    elif "elf" in fmt:
        caps.is_elf = True
    elif "pe" in fmt or "portable executable" in fmt:
        caps.is_pe = True

    mem = handle.program.getMemory()
    block_names_lower = " ".join(block.getName() for block in mem.getBlocks()).lower()

    if any(s in block_names_lower for s in ["swift5", "__swift", "swift_"]):
        caps.has_swift = True

    if any(s in block_names_lower for s in ["__objc_", "objc_class", "objc_data"]):
        caps.has_objc = True

    if deep:
        from pyghidra_lite.hermes import HermesTools
        try:
            hermes_tools = HermesTools(handle)
            if hermes_tools.is_hermes():
                caps.has_hermes = True
        except Exception as e:
            logger.debug(f"Hermes detection failed: {e}")

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


def _format_capabilities(caps: BinaryCapabilities) -> list[str]:
    """Convert BinaryCapabilities to a flat list of strings."""
    result = []
    if caps.is_elf: result.append("ELF")
    if caps.is_macho: result.append("Mach-O")
    if caps.is_pe: result.append("PE")
    if caps.has_swift: result.append("Swift")
    if caps.has_objc: result.append("ObjC")
    if caps.has_hermes: result.append("Hermes")
    return result


# =============================================================================
# SERVER LIFESPAN
# =============================================================================

@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[None]:
    global _backend
    with _backend_lock:
        _init_backend()

    # Clean stale Ghidra lock files from previous sessions
    projects_dir = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
    projects_dir.mkdir(parents=True, exist_ok=True)
    for lock in projects_dir.glob("*/*.lock"):
        lock.unlink(missing_ok=True)
    for lock in projects_dir.glob("*/*.lock~"):
        lock.unlink(missing_ok=True)

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
# CORE TOOLS
# =============================================================================

def _do_import_blocking(p: Path) -> tuple:
    """Blocking import operation (runs in thread pool)."""
    with _backend_lock:
        backend = get_backend()
        handle = backend.import_binary(p)

    caps = _ensure_capabilities(handle)
    return handle, caps


@mcp.tool()
async def import_binary(
    path: str,
    ctx: Context,
    list_tools: bool = False,
) -> dict:
    """Import a binary file for inspection. Returns immediately — no analysis needed.

    After import, all inspection tools are available: strings, imports, exports,
    symbols, memory map, disassembly, decompilation, format-specific tools.

    Args:
        path: Path to binary file.
        list_tools: Include available_tools list (default False, saves tokens).
    """
    try:
        p = _resolve_import_path(path)
    except ValueError as exc:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(exc))) from exc
    if not p.exists():
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Not found: {p}"))

    with open(p, "rb") as f:
        header = f.read(16)

    kind = detect_binary_kind(p, header)
    file_size_mb = p.stat().st_size / (1024 * 1024)

    logger.info(f"Importing {p.name} ({kind}, {file_size_mb:.1f}MB)")

    loop = asyncio.get_event_loop()

    try:
        handle, caps = await loop.run_in_executor(
            _import_executor,
            lambda: _do_import_blocking(p)
        )

        result = {
            "name": handle.name,
            "unit_id": handle.unit_id,
            "kind": kind,
            "size_mb": round(file_size_mb, 1),
            "capabilities": _format_capabilities(caps),
        }

        if list_tools:
            result["available_tools"] = _available_tools(caps)

        return result
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Import failed: {e}")) from e


@mcp.tool()
def list_binaries(ctx: Context, list_tools: bool = False) -> list[dict]:
    """List all imported binaries available for inspection.

    Args:
        list_tools: Include available_tools list per binary (default False, saves tokens).
    """
    def op():
        backend = get_backend()
        results = []
        seen_uids = set()

        for name in backend.list_programs():
            handle = backend.get_program(name)
            seen_uids.add(handle.unit_id)
            caps = _ensure_capabilities(handle)
            entry = {
                "name": handle.name,
                "unit_id": handle.unit_id,
                "status": "ready",
                "capabilities": _format_capabilities(caps),
            }
            if list_tools:
                entry["available_tools"] = _available_tools(caps)
            results.append(entry)

        # On-disk projects not yet loaded
        projects_path = Path(_server_config.project_dir or DEFAULT_PROJECT_DIR)
        if projects_path.exists():
            for dir_entry in projects_path.iterdir():
                uid = dir_entry.name
                if uid in seen_uids or not dir_entry.is_dir():
                    continue
                if not list(dir_entry.glob("*.gpr")):
                    continue
                seen_uids.add(uid)
                results.append({
                    "unit_id": uid,
                    "name": uid,
                    "status": "on_disk",
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

    Note: for stripped binaries without symbols, function discovery is limited
    to entry points and exported symbols. Binaries with debug info or symbol
    tables will show all named functions.

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
) -> DecompiledFunction:
    """Decompile a function.

    Args:
        binary: Binary name.
        function: Function name or address (0x...).
        include_callees: Include list of called functions (default True).
        include_strings: Include string references (default True).
    """
    return _with_handle(
        "decompile",
        binary,
        lambda handle: GhidraTools(handle).decompile_function(
            function,
            include_callees=include_callees,
            include_strings=include_strings,
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
) -> BytesResult:
    """Read raw bytes at address.

    Args:
        binary: Binary name.
        address: Hex address (0x...) or symbol name.
        size: Bytes to read (1-4096).
    """
    return _with_handle(
        "read_bytes",
        binary,
        lambda handle: GhidraTools(handle).read_bytes(address, size),
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
        depth = 5
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
# SURGICAL / OVERVIEW TOOLS
# =============================================================================

@mcp.tool()
def binary_info(binary: str, ctx: Context) -> dict:
    """One-shot overview of a binary. Call this first after import.

    Returns format, architecture, entry point, section summary,
    function/symbol counts, and detected capabilities.

    Args:
        binary: Binary name.
    """
    def op(handle):
        program = handle.program
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        mem = program.getMemory()

        num_functions = fm.getFunctionCount()
        num_symbols = st.getNumSymbols()

        # Sections summary
        sections = []
        for block in mem.getBlocks():
            perms = ""
            if block.isRead():
                perms += "r"
            if block.isWrite():
                perms += "w"
            if block.isExecute():
                perms += "x"
            sections.append({
                "name": block.getName(),
                "size": int(block.getSize()),
                "perms": perms or "---",
            })

        # Entry point
        entry = None
        for func in fm.getFunctions(True):
            if func.getName() in ("main", "_main", "_start", "start", "entry"):
                entry = str(func.getEntryPoint())
                break

        caps = _ensure_capabilities(handle)

        return {
            "name": handle.name,
            "unit_id": handle.unit_id,
            "format": handle.metadata.get("Executable Format", "unknown"),
            "arch": handle.metadata.get("Processor", "unknown"),
            "bits": handle.metadata.get("Address Size", "unknown"),
            "endian": handle.metadata.get("Endian", "unknown"),
            "entry_point": entry,
            "num_functions": num_functions,
            "num_symbols": num_symbols,
            "sections": sections,
            "capabilities": _format_capabilities(caps),
        }

    return _with_handle("binary_info", binary, op)


@mcp.tool()
def find_bytes(
    binary: str,
    pattern: str,
    ctx: Context,
    limit: int = 20,
) -> list[dict]:
    """Search for byte pattern across memory (magic numbers, crypto constants).

    Args:
        binary: Binary name.
        pattern: Hex bytes (e.g. "cafebabe" or "ca fe ba be").
        limit: Max results (default 20).
    """
    return _with_handle(
        "find_bytes",
        binary,
        lambda handle: GhidraTools(handle).find_bytes(pattern, limit=limit),
    )


@mcp.tool()
def entropy_map(binary: str, ctx: Context) -> list[dict]:
    """Per-section entropy to identify packed/encrypted regions.

    High entropy (>7.0) suggests encryption/compression.
    Low entropy (<1.0) is mostly zeros/padding.

    Args:
        binary: Binary name.
    """
    return _with_handle(
        "entropy_map",
        binary,
        lambda handle: GhidraTools(handle).entropy_map(),
    )


@mcp.tool()
def diff_symbols(binary_a: str, binary_b: str, ctx: Context) -> dict:
    """Compare symbol tables of two binaries (patch diffing).

    Args:
        binary_a: First binary name.
        binary_b: Second binary name.

    Returns:
        Added/removed symbols and overlap count.
    """
    def op():
        backend = get_backend()
        handle_a = backend.get_program(binary_a)
        handle_b = backend.get_program(binary_b)

        def get_symbols(program):
            st = program.getSymbolTable()
            return {sym.getName() for sym in st.getAllSymbols(True)}

        syms_a = get_symbols(handle_a.program)
        syms_b = get_symbols(handle_b.program)

        added = sorted(syms_b - syms_a)
        removed = sorted(syms_a - syms_b)

        return {
            "binary_a": handle_a.name,
            "binary_b": handle_b.name,
            "added": added[:100],
            "removed": removed[:100],
            "num_added": len(syms_b - syms_a),
            "num_removed": len(syms_a - syms_b),
            "num_common": len(syms_a & syms_b),
        }

    with _backend_lock:
        return _guarded_tool_call("diff_symbols", op)


# =============================================================================
# ELF TOOLS (Linux binaries)
# =============================================================================

@mcp.tool()
def elf_info(binary: str, ctx: Context) -> dict:
    """Get ELF binary structure summary.

    Args:
        binary: Binary name.
    """
    from pyghidra_lite.formats import ElfTools

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
    from pyghidra_lite.formats import ElfTools

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
    from pyghidra_lite.formats import ElfTools

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
    from pyghidra_lite.formats import ElfTools

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
    from pyghidra_lite.formats import MachOTools

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
    from pyghidra_lite.formats import MachOTools

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
    from pyghidra_lite.formats import MachOTools

    return _with_handle(
        "macho_dylibs",
        binary,
        lambda handle: [d.name for d in MachOTools(handle).list_dylibs()],
    )


# =============================================================================
# SWIFT TOOLS (Available when swift capability detected)
# =============================================================================

@mcp.tool()
def swift_info(
    binary: str,
    ctx: Context,
    pattern: str = "",
    limit: int = 30,
) -> dict:
    """Swift overview: module, types, and functions with demangled names.

    Use `decompile` to decompile individual Swift functions by address.

    Args:
        binary: Binary name.
        pattern: Filter functions/types by name substring.
        limit: Max function results (default 30).
    """
    from pyghidra_lite.lang import SwiftTools

    def op(handle):
        tools = SwiftTools(handle)
        info = tools.get_swift_info()
        functions = tools.list_swift_functions(pattern=pattern, limit=limit)
        types = tools.list_swift_types(limit=limit)
        return {
            "module": info.module_name,
            "num_functions": info.num_swift_functions,
            "sections": info.sections,
            "types": [{"name": t.name, "module": t.module, "kind": t.kind} for t in types],
            "functions": [
                {"demangled": f.demangled, "addr": f.address, "kind": f.kind}
                for f in functions
            ],
        }

    return _with_handle("swift_info", binary, op)


@mcp.tool()
def demangle(name: str, ctx: Context) -> str:
    """Demangle a Swift symbol name.

    Args:
        name: Mangled Swift symbol (e.g., _$s...).
    """
    from pyghidra_lite.lang import demangle_swift
    return demangle_swift(name)


# =============================================================================
# OBJECTIVE-C TOOLS (Available when objc capability detected)
# =============================================================================

@mcp.tool()
def objc_info(
    binary: str,
    ctx: Context,
    pattern: str = "",
    class_name: str | None = None,
    limit: int = 30,
) -> dict:
    """ObjC overview: classes, methods, and framework usage.

    Use `decompile` to decompile individual methods by address.

    Args:
        binary: Binary name.
        pattern: Filter by class/method name.
        class_name: Show methods for a specific class.
        limit: Max results (default 30).
    """
    from pyghidra_lite.lang import ObjCTools

    def op(handle):
        tools = ObjCTools(handle)
        info = tools.get_objc_info()
        result = {
            "num_classes": info.num_classes,
            "num_selectors": info.num_selectors,
            "has_arc": info.has_arc,
            "frameworks": info.frameworks,
        }

        if class_name:
            methods = tools.list_methods(
                class_name=class_name, pattern=pattern, limit=limit
            )
            result["methods"] = [
                {"sig": m.signature, "addr": m.impl_address} for m in methods
            ]
        else:
            classes = tools.list_classes(pattern=pattern, limit=limit)
            result["classes"] = [
                {"name": c.name, "addr": c.address, "methods": len(c.methods)}
                for c in classes
            ]

        return result

    return _with_handle("objc_info", binary, op)


# =============================================================================
# HERMES / REACT NATIVE TOOLS
# =============================================================================

@mcp.tool()
def hermes_info(binary: str, ctx: Context, limit: int = 30) -> dict:
    """React Native / Hermes overview: components, endpoints, and metadata.

    Args:
        binary: Binary name.
        limit: Max results for components/endpoints (default 30).
    """
    from pyghidra_lite.hermes import HermesTools

    def op(handle):
        tools = HermesTools(handle)
        info = tools.get_hermes_info()
        result = {
            "is_hermes": info.is_hermes,
            "bundle_size": info.bundle_size,
        }

        if info.is_hermes:
            result["components"] = tools.find_react_components(limit=limit)
            result["endpoints"] = tools.extract_api_endpoints(limit=limit)

        return result

    return _with_handle("hermes_info", binary, op)


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
    project_name: str,
    project_dir: Path | None,
    ghidra_dir: Path | None,
    runtime_home: Path | None,
    allow_paths: tuple[Path, ...],
    allow_any_path: bool,
    eager_load: bool,
    binaries: tuple[Path, ...],
):
    """Start the MCP server (default when no subcommand given)."""
    global _backend

    if transport != "stdio":
        raise click.ClickException("SSE transport is disabled. Use --transport stdio.")

    logger.info(f"pyghidra-lite v{__version__} (transport={transport})")

    configure_server(
        project_name=project_name,
        project_dir=project_dir,
        ghidra_dir=ghidra_dir,
        runtime_home=runtime_home,
        allow_any_path=allow_any_path,
        allowed_paths=list(allow_paths),
        shared=True,
    )
    _check_prerequisites(ghidra_dir)
    with _backend_lock:
        _backend = _init_backend(eager_load=eager_load)

    # Detect capabilities for all pre-loaded binaries
    for prog_name in _backend.list_programs():
        handle = _backend.get_program(prog_name)
        _ensure_capabilities(handle)
        logger.info(f"Pre-loaded {handle.name} (unit_id={handle.unit_id})")

    # Import binaries from command line
    for binary_path in binaries:
        try:
            handle = _backend.import_binary(binary_path)
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


@cli.command("list")
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=DEFAULT_PROJECT_DIR, envvar="PYGHIDRA_LITE_PROJECT_DIR",
              help="Project directory")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def list_cmd(project_dir, as_json):
    """List cached binaries. No Ghidra needed."""
    import json

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
        info = {
            "unit_id": entry.name,
            "size_mb": round(size / 1024 / 1024, 1),
        }
        entries.append(info)

    if as_json:
        click.echo(json.dumps(entries, indent=2))
    else:
        if not entries:
            click.echo("No cached binaries found.")
            return
        for e in entries:
            click.echo(f"  {e['unit_id']}  {e['size_mb']:>6.1f}MB")


def main():
    """Entry point for pyproject.toml console_scripts."""
    cli()


if __name__ == "__main__":
    main()

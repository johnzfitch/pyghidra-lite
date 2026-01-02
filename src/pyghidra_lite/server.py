"""pyghidra-lite MCP server - focused toolset with smart backend."""

import hashlib
import logging
import sys
import tempfile
import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import click
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_lite import __version__
from pyghidra_lite.backend import GhidraBackend, compute_unit_id
from pyghidra_lite.models import (
    AnalysisProfile,
    AnalysisStatus,
    BinaryMetadata,
    BinaryUnit,
    BytesResult,
    CodeMatch,
    ContainerInfo,
    CrossRef,
    DecompiledFunction,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    Provenance,
    StringXref,
    SymbolInfo,
)
from pyghidra_lite.tools import GhidraTools

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Global backend instance
_backend: GhidraBackend | None = None


def get_backend() -> GhidraBackend:
    """Get the global backend instance."""
    global _backend
    if _backend is None:
        raise RuntimeError("Backend not initialized")
    return _backend


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
    # Check magic bytes for AppImage
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
            if b"AI\x02" in magic:
                return "appimage"
    except Exception:
        pass
    return None


def detect_binary_kind(path: Path, data: bytes | None = None) -> str:
    """Detect binary type from magic bytes."""
    if data is None:
        with open(path, "rb") as f:
            data = f.read(16)

    if data[:4] == b"\x7fELF":
        return "elf"
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",  # Mach-O
                       b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    elif data[:4] == b"\xca\xfe\xba\xbe":  # Fat Mach-O
        return "macho"
    elif data[:2] == b"MZ":
        return "pe"
    elif data[:4] == b"dex\n" or data[:4] == b"dey\n":
        return "dex"
    elif data[:4] == b"PK\x03\x04":
        return "archive"
    return "unknown"


@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[None]:
    yield


mcp = FastMCP("pyghidra-lite", lifespan=server_lifespan)


# =============================================================================
# IMPORT / CONTAINER EXTRACTION
# =============================================================================

@mcp.tool()
def import_binary(
    path: str,
    ctx: Context,
    profile: str = "default",
    extract_containers: bool = True,
) -> ContainerInfo | BinaryUnit:
    """Import a binary or container (APK/IPA/AppImage) for analysis.

    Args:
        path: Path to binary or container.
        profile: Analysis depth - "fast", "default", or "deep".
        extract_containers: Auto-extract APK/IPA/AppImage contents.
    """
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"File not found: {path}"))

    try:
        profile_enum = AnalysisProfile(profile)
    except ValueError:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Invalid profile '{profile}'. Use: fast, default, deep"
        ))

    container_type = detect_container_type(p) if extract_containers else None

    if container_type:
        return _extract_container(p, container_type, profile_enum)
    else:
        return _import_single_binary(p, profile_enum)


def _import_single_binary(path: Path, profile: AnalysisProfile) -> BinaryUnit:
    """Import a single binary file."""
    backend = get_backend()

    with open(path, "rb") as f:
        data = f.read()

    unit_id = compute_unit_id(data)
    kind = detect_binary_kind(path, data[:16])

    logger.info(f"Importing {path.name} ({kind}) with profile={profile.value}")

    try:
        handle = backend.import_binary(path, profile, analyze=True)
        return BinaryUnit(
            unit_id=handle.unit_id,
            name=handle.name,
            path=str(path),
            kind=kind,
            analyzed=handle.analyzed,
            profile=profile,
        )
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Import failed: {e}"))


def _extract_container(path: Path, container_type: str, profile: AnalysisProfile) -> ContainerInfo:
    """Extract binaries from a container."""
    with open(path, "rb") as f:
        asset_id = compute_unit_id(f.read())

    units: list[BinaryUnit] = []

    if container_type in ("apk", "ipa", "zip"):
        units = _extract_zip_container(path, asset_id, container_type, profile)
    elif container_type == "appimage":
        units = _extract_appimage(path, asset_id, profile)

    logger.info(f"Extracted {len(units)} binaries from {path.name}")

    return ContainerInfo(
        asset_id=asset_id,
        container_type=container_type,
        units=units,
    )


def _extract_zip_container(
    path: Path, asset_id: str, container_type: str, profile: AnalysisProfile
) -> list[BinaryUnit]:
    """Extract binaries from APK/IPA/ZIP."""
    backend = get_backend()
    units = []
    interesting_patterns = {
        "apk": ["lib/", "classes", ".dex", ".so"],
        "ipa": ["Payload/", ".app/", "Frameworks/"],
        "zip": [".so", ".dll", ".exe", ".dylib"],
    }
    patterns = interesting_patterns.get(container_type, [])

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if any(p in name for p in patterns) or name.endswith((".so", ".dex", ".dylib")):
                    try:
                        data = zf.read(name)
                        if len(data) < 16:
                            continue
                        kind = detect_binary_kind(Path(name), data[:16])
                        if kind in ("elf", "macho", "pe", "dex"):
                            # Extract to temp and import
                            extracted = tmppath / Path(name).name
                            extracted.write_bytes(data)
                            try:
                                handle = backend.import_binary(extracted, profile, analyze=True)
                                units.append(BinaryUnit(
                                    unit_id=handle.unit_id,
                                    name=handle.name,
                                    path=name,
                                    parent_id=asset_id,
                                    kind=kind,
                                    analyzed=handle.analyzed,
                                    profile=profile,
                                ))
                            except Exception as e:
                                logger.warning(f"Failed to import {name}: {e}")
                    except Exception as e:
                        logger.warning(f"Failed to extract {name}: {e}")

    return units


def _extract_appimage(path: Path, asset_id: str, profile: AnalysisProfile) -> list[BinaryUnit]:
    """Extract binaries from AppImage (squashfs)."""
    logger.warning("AppImage extraction not yet implemented")
    return []


# =============================================================================
# DISCOVERY
# =============================================================================

@mcp.tool()
def list_binaries(ctx: Context) -> list[BinaryUnit]:
    """List all binaries in the project with analysis status."""
    backend = get_backend()
    results = []
    for name in backend.list_programs():
        handle = backend.get_program(name)
        results.append(BinaryUnit(
            unit_id=handle.unit_id,
            name=handle.name,
            path=str(handle.file_path) if handle.file_path else None,
            kind=handle.metadata.get("Executable Format", "unknown"),
            analyzed=handle.analyzed,
            profile=handle.profile,
        ))
    return results


@mcp.tool()
def get_info(binary: str, ctx: Context) -> BinaryMetadata:
    """Get binary metadata including function/symbol counts.

    Args:
        binary: Binary name or unit_id.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    program = handle.program
    fm = program.getFunctionManager()
    st = program.getSymbolTable()

    return BinaryMetadata(
        unit_id=handle.unit_id,
        name=handle.name,
        arch=handle.metadata.get("Processor"),
        bits=int(handle.metadata.get("Address Size", "0").replace(" ", "").rstrip("bit") or 0) or None,
        endian=handle.metadata.get("Endian"),
        format=handle.metadata.get("Executable Format"),
        num_functions=fm.getFunctionCount(),
        num_symbols=st.getNumSymbols(),
        num_strings=None,  # Expensive to compute
        analyzed=handle.analyzed,
        profile=handle.profile,
        provenance=handle.get_provenance(),
    )


@mcp.tool()
def get_status(binary: str, ctx: Context) -> AnalysisStatus:
    """Check analysis status of a binary.

    Args:
        binary: Binary name or unit_id.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    return AnalysisStatus(
        unit_id=handle.unit_id,
        state="ready" if handle.analyzed else "analyzing",
        profile=handle.profile,
        progress=1.0 if handle.analyzed else 0.5,
    )


@mcp.tool()
def list_functions(
    binary: str,
    ctx: Context,
    pattern: str = "",
    limit: int = 50,
    sort_by: str = "name",
) -> list[FunctionInfo]:
    """List functions with metadata for prioritization.

    Args:
        binary: Binary name or unit_id.
        pattern: Filter by name substring.
        limit: Max results.
        sort_by: Sort by "name", "refs_in" (importance), or "refs_out" (complexity).
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    return tools.list_functions(pattern=pattern, limit=limit, sort_by=sort_by)


@mcp.tool()
def list_imports(
    binary: str, ctx: Context, pattern: str = "", limit: int = 50
) -> list[ImportInfo]:
    """List imports with capability tags (crypto, network, file, etc).

    Args:
        binary: Binary name or unit_id.
        pattern: Filter by name/library substring.
        limit: Max results.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    return tools.list_imports(pattern=pattern, limit=limit)


@mcp.tool()
def list_exports(
    binary: str, ctx: Context, pattern: str = "", limit: int = 50
) -> list[ExportInfo]:
    """List exported symbols.

    Args:
        binary: Binary name or unit_id.
        pattern: Filter by name substring.
        limit: Max results.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    return tools.list_exports(pattern=pattern, limit=limit)


# =============================================================================
# ANALYSIS
# =============================================================================

@mcp.tool()
def decompile(binary: str, function: str, ctx: Context) -> DecompiledFunction:
    """Decompile a function with metadata (callees, strings used).

    Args:
        binary: Binary name or unit_id.
        function: Function name or address (0x...).
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    try:
        return tools.decompile_function(function)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))


@mcp.tool()
def get_xrefs(binary: str, target: str, ctx: Context, limit: int = 50) -> list[CrossRef]:
    """Get cross-references TO a target (who calls/uses this).

    Args:
        binary: Binary name or unit_id.
        target: Function name or address.
        limit: Max results.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    try:
        return tools.get_xrefs(target, limit=limit)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))


@mcp.tool()
def get_callees(binary: str, function: str, ctx: Context) -> list[str]:
    """Get functions called BY this function.

    Args:
        binary: Binary name or unit_id.
        function: Function name or address.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    try:
        return tools.get_callees(function)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))


# =============================================================================
# SEARCH
# =============================================================================

@mcp.tool()
def search_functions(
    binary: str, query: str, ctx: Context, limit: int = 10
) -> list[CodeMatch]:
    """Search functions by name pattern (semantic search coming soon).

    Args:
        binary: Binary name or unit_id.
        query: Name pattern to search.
        limit: Max results.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    # For now, just do pattern matching
    functions = tools.list_functions(pattern=query, limit=limit)
    results = []
    for f in functions:
        try:
            decomp = tools.decompile_function(f.name)
            results.append(CodeMatch(
                function=f.name,
                address=f.address,
                stable_id=f.stable_id,
                code=decomp.code[:500] + "..." if len(decomp.code) > 500 else decomp.code,
                score=1.0,
                match_reason=f"Name matches '{query}'",
            ))
        except Exception:
            results.append(CodeMatch(
                function=f.name,
                address=f.address,
                stable_id=f.stable_id,
                code="// Decompilation failed",
                score=0.5,
                match_reason=f"Name matches '{query}'",
            ))
    return results


@mcp.tool()
def search_strings(
    binary: str, query: str, ctx: Context, limit: int = 30
) -> list[StringXref]:
    """Find strings with cross-references (who uses them).

    Args:
        binary: Binary name or unit_id.
        query: String pattern.
        limit: Max results.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    return tools.search_strings(query, limit=limit)


@mcp.tool()
def search_symbols(
    binary: str, query: str, ctx: Context, limit: int = 30
) -> list[SymbolInfo]:
    """Search symbols by name.

    Args:
        binary: Binary name or unit_id.
        query: Name substring (case-insensitive).
        limit: Max results.
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    return tools.search_symbols(query, limit=limit)


# =============================================================================
# DATA
# =============================================================================

@mcp.tool()
def read_bytes(
    binary: str, address: str, size: int, ctx: Context
) -> BytesResult:
    """Read raw bytes at address.

    Args:
        binary: Binary name or unit_id.
        address: Hex address (0x...).
        size: Bytes to read (max 4096).
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    try:
        return tools.read_bytes(address, size)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))


@mcp.tool()
def read_string(binary: str, address: str, ctx: Context) -> str:
    """Read null-terminated string at address.

    Args:
        binary: Binary name or unit_id.
        address: Hex address (0x...).
    """
    backend = get_backend()
    try:
        handle = backend.get_program(binary)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))

    tools = GhidraTools(handle)
    try:
        return tools.read_string(address)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))


# =============================================================================
# PROJECT
# =============================================================================

@mcp.tool()
def delete_binary(binary: str, ctx: Context) -> str:
    """Remove binary from project.

    Args:
        binary: Binary name or unit_id.
    """
    backend = get_backend()
    if backend.delete_program(binary):
        return f"Deleted {binary}"
    else:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Failed to delete {binary}"))


@mcp.tool()
def reanalyze(
    binary: str, ctx: Context, profile: str = "deep"
) -> AnalysisStatus:
    """Re-run analysis with a different profile.

    Args:
        binary: Binary name or unit_id.
        profile: New profile - "fast", "default", or "deep".
    """
    backend = get_backend()
    try:
        profile_enum = AnalysisProfile(profile)
    except ValueError:
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message=f"Invalid profile '{profile}'. Use: fast, default, deep"
        ))

    try:
        handle = backend.get_program(binary)
        backend.analyze_program(handle.name, profile_enum)
        return AnalysisStatus(
            unit_id=handle.unit_id,
            state="ready",
            profile=profile_enum,
            progress=1.0,
        )
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))


# =============================================================================
# CLI
# =============================================================================

@click.command()
@click.version_option(__version__, "-v", "--version")
@click.option("-t", "--transport", type=click.Choice(["stdio", "sse"]), default="stdio")
@click.option("-p", "--port", type=int, default=8000)
@click.option("--host", type=str, default="127.0.0.1")
@click.option("--profile", type=click.Choice(["fast", "default", "deep"]), default="default",
              help="Default analysis profile")
@click.option("--project-name", type=str, default="pyghidra_lite",
              help="Ghidra project name")
@click.option("--project-dir", type=click.Path(path_type=Path), default=None,
              help="Project directory (default: ~/.local/share/pyghidra-lite/projects)")
@click.argument("binaries", nargs=-1, type=click.Path(exists=True, path_type=Path))
def main(
    transport: str,
    port: int,
    host: str,
    profile: str,
    project_name: str,
    project_dir: Path | None,
    binaries: tuple[Path, ...],
):
    """pyghidra-lite: Lightweight RE MCP server.

    Import binaries at startup or use import_binary tool later.
    """
    global _backend

    logger.info(f"pyghidra-lite v{__version__} (profile={profile})")

    # Initialize backend
    profile_enum = AnalysisProfile(profile)
    _backend = GhidraBackend(
        project_name=project_name,
        project_dir=project_dir,
        default_profile=profile_enum,
    )
    _backend.start()

    # Import any binaries passed on command line
    for binary_path in binaries:
        try:
            _backend.import_binary(binary_path, profile_enum, analyze=True)
        except Exception as e:
            logger.error(f"Failed to import {binary_path}: {e}")

    logger.info(f"Ready. {len(_backend.programs)} programs loaded.")

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        else:
            mcp.run(transport="sse", host=host, port=port)
    finally:
        if _backend:
            _backend.close()


if __name__ == "__main__":
    main()

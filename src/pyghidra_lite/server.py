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

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_context = None


def compute_unit_id(data: bytes) -> str:
    """Content-addressed ID for a binary."""
    return hashlib.sha256(data).hexdigest()[:16]


def compute_stable_id(unit_id: str, address: str) -> str:
    """Stable function ID that survives renames."""
    return hashlib.sha256(f"{unit_id}:{address}".encode()).hexdigest()[:16]


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
    with open(path, "rb") as f:
        data = f.read()

    unit_id = compute_unit_id(data)
    kind = detect_binary_kind(path, data[:16])

    # TODO: Actually import into Ghidra project
    logger.info(f"Importing {path.name} ({kind}) with profile={profile.value}")

    return BinaryUnit(
        unit_id=unit_id,
        name=path.name,
        path=str(path),
        kind=kind,
        analyzed=False,
        profile=profile,
    )


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
    units = []
    interesting_patterns = {
        "apk": ["lib/", "classes", ".dex", ".so"],
        "ipa": ["Payload/", ".app/", "Frameworks/"],
        "zip": [".so", ".dll", ".exe", ".dylib"],
    }
    patterns = interesting_patterns.get(container_type, [])

    with zipfile.ZipFile(path, "r") as zf:
        for name in zf.namelist():
            if any(p in name for p in patterns) or name.endswith((".so", ".dex", ".dylib")):
                try:
                    data = zf.read(name)
                    if len(data) < 16:
                        continue
                    kind = detect_binary_kind(Path(name), data[:16])
                    if kind in ("elf", "macho", "pe", "dex"):
                        units.append(BinaryUnit(
                            unit_id=compute_unit_id(data),
                            name=Path(name).name,
                            path=name,
                            parent_id=asset_id,
                            kind=kind,
                            analyzed=False,
                            profile=profile,
                        ))
                except Exception as e:
                    logger.warning(f"Failed to extract {name}: {e}")

    return units


def _extract_appimage(path: Path, asset_id: str, profile: AnalysisProfile) -> list[BinaryUnit]:
    """Extract binaries from AppImage (squashfs)."""
    # TODO: Use squashfs-tools or appimage-extract
    logger.warning("AppImage extraction not yet implemented")
    return []


# =============================================================================
# DISCOVERY
# =============================================================================

@mcp.tool()
def list_binaries(ctx: Context) -> list[BinaryUnit]:
    """List all binaries in the project with analysis status."""
    # TODO: Query Ghidra project
    return []


@mcp.tool()
def get_info(binary: str, ctx: Context) -> BinaryMetadata:
    """Get binary metadata including function/symbol counts.

    Args:
        binary: Binary name or unit_id.
    """
    # TODO: Query Ghidra project
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


@mcp.tool()
def get_status(binary: str, ctx: Context) -> AnalysisStatus:
    """Check analysis status of a binary.

    Args:
        binary: Binary name or unit_id.
    """
    # TODO: Query analysis state
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


@mcp.tool()
def list_functions(
    binary: str,
    ctx: Context,
    pattern: str = "",
    limit: int = 50,
    sort_by: str = "name",
) -> list[FunctionInfo]:
    """List functions with metadata annotations for prioritization.

    Args:
        binary: Binary name or unit_id.
        pattern: Filter by name substring.
        limit: Max results.
        sort_by: Sort by "name", "refs_in" (importance), or "refs_out" (complexity).
    """
    # TODO: Query Ghidra, include refs_in/refs_out/has_strings/is_library
    return []


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
    # TODO: Query Ghidra, add tags for known APIs
    return []


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
    # TODO: Query Ghidra
    return []


# =============================================================================
# ANALYSIS
# =============================================================================

@mcp.tool()
async def decompile(binary: str, function: str, ctx: Context) -> DecompiledFunction:
    """Decompile a function with metadata (callees, strings used).

    Args:
        binary: Binary name or unit_id.
        function: Function name or address (0x...).
    """
    # TODO: Decompile and extract callees + strings
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


@mcp.tool()
def get_xrefs(binary: str, target: str, ctx: Context, limit: int = 50) -> list[CrossRef]:
    """Get cross-references TO a target (who calls/uses this).

    Args:
        binary: Binary name or unit_id.
        target: Function name or address.
        limit: Max results.
    """
    # TODO: Query xrefs
    return []


@mcp.tool()
def get_callees(binary: str, function: str, ctx: Context) -> list[str]:
    """Get functions called BY this function.

    Args:
        binary: Binary name or unit_id.
        function: Function name or address.
    """
    # TODO: Extract callees from function
    return []


# =============================================================================
# SEARCH
# =============================================================================

@mcp.tool()
def search_functions(
    binary: str, query: str, ctx: Context, limit: int = 10
) -> list[CodeMatch]:
    """Semantic search: find functions by description or code pattern.

    Args:
        binary: Binary name or unit_id.
        query: Natural language or code pattern.
        limit: Max results.
    """
    # TODO: Vector search over decompiled code
    return []


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
    # TODO: Search strings, include xrefs and looks_like hints
    return []


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
    # TODO: Query symbol table
    return []


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
    # TODO: Read from Ghidra memory
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


@mcp.tool()
def read_string(binary: str, address: str, ctx: Context) -> str:
    """Read null-terminated string at address.

    Args:
        binary: Binary name or unit_id.
        address: Hex address (0x...).
    """
    # TODO: Read string from Ghidra
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


# =============================================================================
# PROJECT
# =============================================================================

@mcp.tool()
def delete_binary(binary: str, ctx: Context) -> str:
    """Remove binary from project.

    Args:
        binary: Binary name or unit_id.
    """
    # TODO: Remove from Ghidra project
    return f"Deleted {binary}"


@mcp.tool()
def reanalyze(
    binary: str, ctx: Context, profile: str = "deep"
) -> AnalysisStatus:
    """Re-run analysis with a different profile.

    Args:
        binary: Binary name or unit_id.
        profile: New profile - "fast", "default", or "deep".
    """
    # TODO: Re-run Ghidra analysis
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


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
@click.argument("binaries", nargs=-1, type=click.Path(exists=True, path_type=Path))
def main(transport: str, port: int, host: str, profile: str, binaries: tuple[Path, ...]):
    """pyghidra-lite: Lightweight RE MCP server."""
    logger.info(f"pyghidra-lite v{__version__} (profile={profile})")

    # TODO: Initialize Ghidra context, import binaries with profile

    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=host, port=port)


if __name__ == "__main__":
    main()

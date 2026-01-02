"""pyghidra-lite MCP server with optimized context and extended RE tools."""

import logging
import sys
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
    BinaryMetadata,
    BinaryMetadataExtended,
    BytesResult,
    CodeMatch,
    CrossRef,
    DecompiledFunction,
    ELFSection,
    Entitlement,
    EntropyRegion,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    MachOSection,
    MachOSegment,
    ObjCClass,
    ObjCMethod,
    ProgramInfo,
    SharedLibrary,
    StringMatch,
    StringXref,
    SwiftType,
    SymbolInfo,
    VulnPattern,
)

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Lazy imports for optional dependencies
_lief = None
_capstone = None


def get_lief():
    global _lief
    if _lief is None:
        try:
            import lief
            _lief = lief
        except ImportError:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message="lief not installed. Run: pip install pyghidra-lite[ios]"
            ))
    return _lief


# Global context placeholder
_context = None


@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[None]:
    yield


mcp = FastMCP("pyghidra-lite", lifespan=server_lifespan)


# =============================================================================
# CORE TOOLS (optimized from pyghidra-mcp)
# =============================================================================

@mcp.tool()
async def decompile(binary: str, function: str, ctx: Context) -> DecompiledFunction:
    """Decompile a function to pseudo-C.

    Args:
        binary: Binary name.
        function: Function name or address.
    """
    # TODO: implement with pyghidra
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not yet implemented"))


@mcp.tool()
def list_binaries(ctx: Context) -> list[ProgramInfo]:
    """List all binaries in the project."""
    # TODO: implement
    return []


@mcp.tool()
def get_metadata(binary: str, ctx: Context, extended: bool = False) -> BinaryMetadata:
    """Get binary metadata. Set extended=True for hashes and full details.

    Args:
        binary: Binary name.
        extended: Include hashes, dates, compiler info.
    """
    # TODO: implement
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not yet implemented"))


@mcp.tool()
def search_symbols(binary: str, query: str, ctx: Context, limit: int = 25) -> list[SymbolInfo]:
    """Search symbols by name substring (case-insensitive).

    Args:
        binary: Binary name.
        query: Search substring.
        limit: Max results.
    """
    # TODO: implement
    return []


@mcp.tool()
def search_code(binary: str, query: str, ctx: Context, limit: int = 5) -> list[CodeMatch]:
    """Semantic search over decompiled code using vector similarity.

    Args:
        binary: Binary name.
        query: Code pattern or description.
        limit: Max results.
    """
    # TODO: implement
    return []


@mcp.tool()
def list_exports(binary: str, ctx: Context, pattern: str = ".*", limit: int = 50) -> list[ExportInfo]:
    """List exported symbols. Use pattern to filter.

    Args:
        binary: Binary name.
        pattern: Regex to filter names.
        limit: Max results.
    """
    # TODO: implement
    return []


@mcp.tool()
def list_imports(binary: str, ctx: Context, pattern: str = ".*", limit: int = 50) -> list[ImportInfo]:
    """List imported symbols. Use pattern to filter.

    Args:
        binary: Binary name.
        pattern: Regex to filter names.
        limit: Max results.
    """
    # TODO: implement
    return []


@mcp.tool()
def get_xrefs(binary: str, target: str, ctx: Context) -> list[CrossRef]:
    """Get cross-references to a function, symbol, or address.

    Args:
        binary: Binary name.
        target: Function name, symbol, or address (0x...).
    """
    # TODO: implement
    return []


@mcp.tool()
def search_strings(binary: str, query: str, ctx: Context, limit: int = 50) -> list[StringMatch]:
    """Search strings in binary.

    Args:
        binary: Binary name.
        query: Search pattern.
        limit: Max results.
    """
    # TODO: implement
    return []


@mcp.tool()
def read_bytes(binary: str, address: str, size: int, ctx: Context) -> BytesResult:
    """Read raw bytes from memory.

    Args:
        binary: Binary name.
        address: Address (hex with 0x prefix).
        size: Bytes to read (max 8192).
    """
    # TODO: implement
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not yet implemented"))


@mcp.tool()
def import_binary(path: str, ctx: Context) -> str:
    """Import a binary into the project.

    Args:
        path: Path to binary file.
    """
    # TODO: implement
    return f"Importing {path} in background..."


# =============================================================================
# iOS / MACH-O TOOLS
# =============================================================================

@mcp.tool()
def macho_segments(binary: str, ctx: Context) -> list[MachOSegment]:
    """List Mach-O segments (__TEXT, __DATA, etc.).

    Args:
        binary: Binary name (must be Mach-O).
    """
    lief = get_lief()
    # TODO: implement with lief
    return []


@mcp.tool()
def macho_sections(binary: str, ctx: Context, segment: str | None = None) -> list[MachOSection]:
    """List Mach-O sections. Optionally filter by segment.

    Args:
        binary: Binary name.
        segment: Filter by segment name (e.g., __TEXT).
    """
    lief = get_lief()
    # TODO: implement
    return []


@mcp.tool()
def objc_classes(binary: str, ctx: Context, pattern: str = ".*") -> list[ObjCClass]:
    """List Objective-C classes with methods and properties.

    Args:
        binary: Binary name.
        pattern: Regex to filter class names.
    """
    # TODO: implement - parse __objc_classlist
    return []


@mcp.tool()
def objc_methods(binary: str, class_name: str, ctx: Context) -> list[ObjCMethod]:
    """List methods for an Objective-C class.

    Args:
        binary: Binary name.
        class_name: Class to inspect.
    """
    # TODO: implement
    return []


@mcp.tool()
def objc_selectors(binary: str, ctx: Context, pattern: str = ".*") -> list[str]:
    """Search Objective-C selectors.

    Args:
        binary: Binary name.
        pattern: Regex to filter selectors.
    """
    # TODO: implement - parse __objc_selrefs
    return []


@mcp.tool()
def swift_types(binary: str, ctx: Context, pattern: str = ".*") -> list[SwiftType]:
    """List Swift types with demangled names.

    Args:
        binary: Binary name.
        pattern: Regex to filter type names.
    """
    # TODO: implement - parse Swift metadata
    return []


@mcp.tool()
def ios_entitlements(binary: str, ctx: Context) -> list[Entitlement]:
    """Extract iOS entitlements from binary.

    Args:
        binary: Binary name.
    """
    lief = get_lief()
    # TODO: implement
    return []


@mcp.tool()
def ios_info_plist(path: str, ctx: Context) -> dict:
    """Parse Info.plist from iOS app bundle.

    Args:
        path: Path to .app bundle or Info.plist.
    """
    # TODO: implement
    return {}


# =============================================================================
# LINUX / ELF TOOLS
# =============================================================================

@mcp.tool()
def elf_sections(binary: str, ctx: Context) -> list[ELFSection]:
    """List ELF sections (.text, .data, .rodata, etc.).

    Args:
        binary: Binary name.
    """
    lief = get_lief()
    # TODO: implement
    return []


@mcp.tool()
def elf_dependencies(binary: str, ctx: Context) -> list[SharedLibrary]:
    """List shared library dependencies (like ldd).

    Args:
        binary: Binary name.
    """
    lief = get_lief()
    # TODO: implement
    return []


@mcp.tool()
def appimage_info(path: str, ctx: Context) -> dict:
    """Extract AppImage metadata and list contents.

    Args:
        path: Path to .AppImage file.
    """
    # TODO: implement - extract squashfs, parse desktop file
    return {}


# =============================================================================
# ANALYSIS TOOLS
# =============================================================================

@mcp.tool()
def analyze_entropy(binary: str, ctx: Context, threshold: float = 7.0) -> list[EntropyRegion]:
    """Find high-entropy regions (encrypted/compressed data).

    Args:
        binary: Binary name.
        threshold: Entropy threshold (0-8, default 7.0 for likely encrypted).
    """
    # TODO: implement
    return []


@mcp.tool()
def find_vuln_patterns(binary: str, ctx: Context) -> list[VulnPattern]:
    """Detect common vulnerability patterns (format strings, unchecked buffers).

    Args:
        binary: Binary name.
    """
    # TODO: implement pattern matching for:
    # - printf family with non-constant format
    # - strcpy/strcat/sprintf usage
    # - gets() calls
    # - malloc without null check
    return []


@mcp.tool()
def string_xrefs(binary: str, ctx: Context, pattern: str = ".*", limit: int = 50) -> list[StringXref]:
    """Find strings with their cross-references (who uses them).

    Args:
        binary: Binary name.
        pattern: Regex to filter strings.
        limit: Max results.
    """
    # TODO: implement
    return []


@mcp.tool()
def list_functions(binary: str, ctx: Context, pattern: str = ".*", limit: int = 100) -> list[FunctionInfo]:
    """List functions with addresses and sizes.

    Args:
        binary: Binary name.
        pattern: Regex to filter names.
        limit: Max results.
    """
    # TODO: implement
    return []


@mcp.tool()
def compare_functions(binary1: str, func1: str, binary2: str, func2: str, ctx: Context) -> dict:
    """Compare two functions for similarity (diffing).

    Args:
        binary1: First binary.
        func1: Function in first binary.
        binary2: Second binary.
        func2: Function in second binary.
    """
    # TODO: implement basic diff
    return {"similarity": 0.0, "diff": ""}


# =============================================================================
# GAME FILE TOOLS (stubs for future implementation)
# =============================================================================

@mcp.tool()
def unity_assets(path: str, ctx: Context) -> list[dict]:
    """List assets in Unity AssetBundle.

    Args:
        path: Path to .assets or .bundle file.
    """
    # TODO: implement with UnityPy
    return []


@mcp.tool()
def unreal_pak(path: str, ctx: Context) -> list[dict]:
    """List contents of Unreal Engine .pak file.

    Args:
        path: Path to .pak file.
    """
    # TODO: implement
    return []


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

@click.command()
@click.version_option(__version__, "-v", "--version")
@click.option("-t", "--transport", type=click.Choice(["stdio", "sse"]), default="stdio")
@click.option("-p", "--port", type=int, default=8000)
@click.option("--host", type=str, default="127.0.0.1")
@click.argument("binaries", nargs=-1, type=click.Path(exists=True, path_type=Path))
def main(transport: str, port: int, host: str, binaries: tuple[Path, ...]):
    """pyghidra-lite: Lightweight RE MCP server."""
    logger.info(f"Starting pyghidra-lite v{__version__}")

    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=host, port=port)


if __name__ == "__main__":
    main()

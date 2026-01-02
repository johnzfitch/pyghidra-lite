"""pyghidra-lite MCP server - focused toolset for agent-driven RE."""

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
    BytesResult,
    CodeMatch,
    CrossRef,
    DecompiledFunction,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    ProgramInfo,
    StringXref,
    SymbolInfo,
)

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_context = None


@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[None]:
    yield


mcp = FastMCP("pyghidra-lite", lifespan=server_lifespan)


# =============================================================================
# DISCOVERY - What's in this binary?
# =============================================================================

@mcp.tool()
def list_binaries(ctx: Context) -> list[ProgramInfo]:
    """List binaries in project with analysis status."""
    return []


@mcp.tool()
def get_info(binary: str, ctx: Context) -> BinaryMetadata:
    """Get binary info: architecture, format, function/symbol counts."""
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


@mcp.tool()
def list_functions(
    binary: str, ctx: Context, pattern: str = "", limit: int = 50
) -> list[FunctionInfo]:
    """List functions. Filter by name pattern.

    Args:
        binary: Binary name.
        pattern: Filter by substring (empty = all).
        limit: Max results.
    """
    return []


@mcp.tool()
def list_imports(binary: str, ctx: Context, pattern: str = "", limit: int = 50) -> list[ImportInfo]:
    """List imported functions. These reveal external dependencies and capabilities.

    Args:
        binary: Binary name.
        pattern: Filter by name/library substring.
        limit: Max results.
    """
    return []


@mcp.tool()
def list_exports(binary: str, ctx: Context, pattern: str = "", limit: int = 50) -> list[ExportInfo]:
    """List exported symbols (API surface of the binary).

    Args:
        binary: Binary name.
        pattern: Filter by name substring.
        limit: Max results.
    """
    return []


# =============================================================================
# ANALYSIS - Understand specific code
# =============================================================================

@mcp.tool()
async def decompile(binary: str, function: str, ctx: Context) -> DecompiledFunction:
    """Decompile a function to pseudo-C code.

    Args:
        binary: Binary name.
        function: Function name or address (0x...).
    """
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


@mcp.tool()
def get_xrefs(binary: str, target: str, ctx: Context) -> list[CrossRef]:
    """Get cross-references TO a function/symbol/address. Shows callers.

    Args:
        binary: Binary name.
        target: Function name or address.
    """
    return []


@mcp.tool()
def get_callees(binary: str, function: str, ctx: Context) -> list[str]:
    """Get functions called BY a function. Shows what it depends on.

    Args:
        binary: Binary name.
        function: Function name or address.
    """
    return []


# =============================================================================
# SEARCH - Find relevant code
# =============================================================================

@mcp.tool()
def search_functions(binary: str, query: str, ctx: Context, limit: int = 10) -> list[CodeMatch]:
    """Semantic search: find functions by description or code pattern.

    Args:
        binary: Binary name.
        query: Natural language or code pattern (e.g., "decrypt data", "malloc without free").
        limit: Max results.
    """
    return []


@mcp.tool()
def search_strings(
    binary: str, query: str, ctx: Context, with_xrefs: bool = True, limit: int = 30
) -> list[StringXref]:
    """Find strings and which functions reference them.

    Args:
        binary: Binary name.
        query: String pattern to search.
        with_xrefs: Include referencing functions (recommended).
        limit: Max results.
    """
    return []


@mcp.tool()
def search_symbols(binary: str, query: str, ctx: Context, limit: int = 30) -> list[SymbolInfo]:
    """Search all symbols (functions, labels, data) by name.

    Args:
        binary: Binary name.
        query: Name substring (case-insensitive).
        limit: Max results.
    """
    return []


# =============================================================================
# DATA - Read raw binary data
# =============================================================================

@mcp.tool()
def read_bytes(binary: str, address: str, size: int, ctx: Context) -> BytesResult:
    """Read raw bytes at address. Useful for examining data structures.

    Args:
        binary: Binary name.
        address: Hex address (0x...).
        size: Bytes to read (max 4096).
    """
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


@mcp.tool()
def read_string(binary: str, address: str, ctx: Context) -> str:
    """Read null-terminated string at address.

    Args:
        binary: Binary name.
        address: Hex address (0x...).
    """
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="Not implemented"))


# =============================================================================
# PROJECT - Manage binaries
# =============================================================================

@mcp.tool()
def import_binary(path: str, ctx: Context) -> str:
    """Import and analyze a binary file.

    Args:
        path: Path to binary.
    """
    return f"Importing {path}..."


@mcp.tool()
def delete_binary(binary: str, ctx: Context) -> str:
    """Remove binary from project.

    Args:
        binary: Binary name.
    """
    return f"Deleted {binary}"


# =============================================================================
# CLI
# =============================================================================

@click.command()
@click.version_option(__version__, "-v", "--version")
@click.option("-t", "--transport", type=click.Choice(["stdio", "sse"]), default="stdio")
@click.option("-p", "--port", type=int, default=8000)
@click.option("--host", type=str, default="127.0.0.1")
@click.argument("binaries", nargs=-1, type=click.Path(exists=True, path_type=Path))
def main(transport: str, port: int, host: str, binaries: tuple[Path, ...]):
    """pyghidra-lite: Lightweight RE MCP server."""
    logger.info(f"pyghidra-lite v{__version__}")
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=host, port=port)


if __name__ == "__main__":
    main()

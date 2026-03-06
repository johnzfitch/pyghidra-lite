"""Models with metadata annotations, stable IDs, and provenance."""

from enum import Enum

from pydantic import BaseModel


class AnalysisProfile(str, Enum):
    """Analysis depth profiles."""
    FAST = "fast"        # Quick triage, minimal decompiler analysis
    DEFAULT = "default"  # Balanced: good decompilation without full analysis
    DEEP = "deep"        # Thorough: full analysis for obfuscated code


class Provenance(BaseModel):
    """Analysis provenance for reproducibility."""
    unit_id: str                    # Content-addressed ID for the binary
    profile: AnalysisProfile        # Analysis profile used
    ghidra_version: str | None = None
    tool_version: str | None = None


# =============================================================================
# BINARY / PROJECT MODELS
# =============================================================================

class BinaryUnit(BaseModel):
    """A single analyzable binary (may be extracted from container)."""
    unit_id: str                    # sha256 of binary content
    name: str                       # Display name
    path: str | None = None         # Original path or path in container
    parent_id: str | None = None    # If extracted from APK/IPA/AppImage
    kind: str = "unknown"           # elf, macho, pe, dex, archive
    arch: str | None = None         # x86_64, arm64, etc.
    analyzed: bool = False
    profile: AnalysisProfile | None = None


class ContainerInfo(BaseModel):
    """Info about an extracted container (APK/IPA/AppImage)."""
    asset_id: str                   # sha256 of container
    container_type: str             # apk, ipa, appimage, zip
    units: list[BinaryUnit] = []    # Extracted binaries


class BinaryMetadata(BaseModel):
    """Binary metadata with analysis metrics."""
    unit_id: str
    name: str | None = None
    arch: str | None = None
    bits: int | None = None
    endian: str | None = None
    format: str | None = None       # ELF, Mach-O, PE, DEX
    num_functions: int | None = None
    num_symbols: int | None = None
    num_strings: int | None = None
    analyzed: bool = False
    profile: AnalysisProfile | None = None
    provenance: Provenance | None = None


# =============================================================================
# FUNCTION MODELS (with metadata annotations)
# =============================================================================

class FunctionInfo(BaseModel):
    """Function with metadata for agent prioritization."""
    name: str
    address: str
    stable_id: str | None = None    # sha256(unit_id:address) - survives renames
    size: int | None = None
    # Metadata annotations (helps agent prioritize)
    refs_in: int | None = None      # How many callers (high = important/utility)
    refs_out: int | None = None     # How many callees (high = orchestrator)
    has_strings: bool | None = None # References string literals
    is_library: bool | None = None  # Identified as known library code (via FIDB)
    is_thunk: bool | None = None    # Simple wrapper/trampoline


class DecompiledFunction(BaseModel):
    """Decompiled function with provenance."""
    name: str
    address: str
    stable_id: str | None = None
    signature: str | None = None
    code: str
    # Metadata
    refs_in: int | None = None
    refs_out: int | None = None
    callees: list[str] | None = None  # Names of called functions
    strings_used: list[str] | None = None  # String literals referenced
    provenance: Provenance | None = None


# =============================================================================
# SYMBOL / REFERENCE MODELS
# =============================================================================

class SymbolInfo(BaseModel):
    """Symbol with type info."""
    name: str
    address: str
    type: str                       # function, label, data, external
    is_library: bool | None = None  # Known library symbol


class ExportInfo(BaseModel):
    """Exported symbol."""
    name: str
    address: str


class ImportInfo(BaseModel):
    """Imported symbol - reveals capabilities."""
    name: str
    library: str
    # Common capability tags (optional, for agent hints)
    tags: list[str] | None = None   # e.g., ["crypto", "network", "file"]


class CrossRef(BaseModel):
    """Cross-reference with context."""
    from_addr: str
    to_addr: str
    type: str                       # call, jump, data, read, write
    from_func: str | None = None    # Containing function name


# =============================================================================
# SEARCH RESULTS
# =============================================================================

class CodeMatch(BaseModel):
    """Semantic search result."""
    function: str
    address: str
    stable_id: str | None = None
    code: str
    score: float
    # Why this matched (for agent context)
    match_reason: str | None = None


class StringXref(BaseModel):
    """String with cross-references - key for understanding behavior."""
    value: str
    address: str
    refs: list[str] = []            # Function names that reference this
    # Hints
    looks_like: str | None = None   # url, path, key, error, format_string
    section: str | None = None      # ".rodata", ".strtab", ".data", etc.


class EmbeddedRuntime(BaseModel):
    """Detected embedded runtime payload within a binary."""
    type: str            # "bunfs", "electron_asar", "upx", etc.
    confidence: str      # "high" | "medium" | "low"
    strategy: str        # "search_payload" | "unpack_first" | "external_tools"
    payload_offset: str | None = None  # Only present when strategy == "search_payload"


# =============================================================================
# DATA ACCESS
# =============================================================================

class BytesResult(BaseModel):
    """Raw bytes with interpretation hints."""
    address: str
    size: int
    hex: str
    ascii: str | None = None        # Printable representation
    provenance: Provenance | None = None


# =============================================================================
# ANALYSIS RESULTS
# =============================================================================

class AnalysisStatus(BaseModel):
    """Status of import/analysis job."""
    unit_id: str
    state: str                      # queued, importing, analyzing, ready, failed
    profile: AnalysisProfile
    progress: float | None = None   # 0.0-1.0
    error: str | None = None

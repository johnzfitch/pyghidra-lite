"""Optimized Pydantic models with minimal context overhead."""

from pydantic import BaseModel


# Core decompilation models
class DecompiledFunction(BaseModel):
    """Decompiled function with pseudo-C code."""
    name: str
    code: str
    signature: str | None = None


class FunctionInfo(BaseModel):
    """Basic function information."""
    name: str
    address: str
    size: int | None = None


# Program/binary models
class ProgramInfo(BaseModel):
    """Binary loaded in project."""
    name: str
    path: str | None = None
    analyzed: bool = False
    has_code_index: bool = False
    has_string_index: bool = False


class BinaryMetadata(BaseModel):
    """Essential binary metadata. Use get_extended_metadata for full details."""
    name: str | None = None
    processor: str | None = None
    endian: str | None = None
    address_size: int | None = None
    format: str | None = None
    num_functions: int | None = None
    num_symbols: int | None = None
    analyzed: bool | None = None


class BinaryMetadataExtended(BinaryMetadata):
    """Full metadata including hashes and compiler info."""
    language_id: str | None = None
    compiler_id: str | None = None
    compiler: str | None = None
    min_address: str | None = None
    max_address: str | None = None
    num_bytes: int | None = None
    num_instructions: int | None = None
    num_data_types: int | None = None
    md5: str | None = None
    sha256: str | None = None
    relocatable: bool | None = None
    created: str | None = None
    ghidra_version: str | None = None


# Symbol and reference models
class SymbolInfo(BaseModel):
    """Symbol in binary."""
    name: str
    address: str
    type: str
    namespace: str = ""
    refs: int = 0


class ExportInfo(BaseModel):
    """Exported symbol."""
    name: str
    address: str


class ImportInfo(BaseModel):
    """Imported symbol."""
    name: str
    library: str


class CrossRef(BaseModel):
    """Cross-reference."""
    from_addr: str
    to_addr: str
    type: str
    function: str | None = None


# Search result models
class CodeMatch(BaseModel):
    """Semantic code search result."""
    function: str
    code: str
    score: float


class StringMatch(BaseModel):
    """String search result."""
    value: str
    address: str
    score: float = 1.0


# iOS-specific models
class ObjCClass(BaseModel):
    """Objective-C class."""
    name: str
    superclass: str | None = None
    methods: list[str] = []
    properties: list[str] = []
    protocols: list[str] = []


class ObjCMethod(BaseModel):
    """Objective-C method."""
    selector: str
    address: str
    class_name: str
    is_class_method: bool = False


class SwiftType(BaseModel):
    """Swift type information."""
    name: str
    demangled: str
    kind: str  # class, struct, enum, protocol


class MachOSegment(BaseModel):
    """Mach-O segment."""
    name: str
    vmaddr: str
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: str
    initprot: str


class MachOSection(BaseModel):
    """Mach-O section."""
    name: str
    segment: str
    address: str
    size: int
    type: str


class Entitlement(BaseModel):
    """iOS entitlement."""
    key: str
    value: str | bool | list


# Linux/ELF models
class ELFSection(BaseModel):
    """ELF section."""
    name: str
    type: str
    address: str
    size: int
    flags: str


class SharedLibrary(BaseModel):
    """Shared library dependency."""
    name: str
    path: str | None = None


# Analysis models
class EntropyRegion(BaseModel):
    """Region with entropy analysis."""
    address: str
    size: int
    entropy: float
    likely_type: str  # code, data, encrypted, compressed, padding


class VulnPattern(BaseModel):
    """Potential vulnerability pattern."""
    type: str  # buffer_overflow, format_string, use_after_free, etc.
    address: str
    function: str
    confidence: float
    description: str


class StringXref(BaseModel):
    """String with cross-references."""
    value: str
    address: str
    xrefs: list[str]  # functions that reference this string


# Memory read
class BytesResult(BaseModel):
    """Raw bytes from memory."""
    address: str
    size: int
    hex: str

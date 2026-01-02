"""Minimal models for agent-driven RE."""

from pydantic import BaseModel


class DecompiledFunction(BaseModel):
    """Decompiled function."""
    name: str
    code: str
    signature: str | None = None


class FunctionInfo(BaseModel):
    """Function summary."""
    name: str
    address: str
    size: int | None = None


class ProgramInfo(BaseModel):
    """Binary in project."""
    name: str
    path: str | None = None
    analyzed: bool = False


class BinaryMetadata(BaseModel):
    """Binary metadata."""
    name: str | None = None
    arch: str | None = None
    bits: int | None = None
    endian: str | None = None
    format: str | None = None
    num_functions: int | None = None
    num_symbols: int | None = None


class SymbolInfo(BaseModel):
    """Symbol."""
    name: str
    address: str
    type: str


class ExportInfo(BaseModel):
    """Export."""
    name: str
    address: str


class ImportInfo(BaseModel):
    """Import."""
    name: str
    library: str


class CrossRef(BaseModel):
    """Cross-reference."""
    from_addr: str
    to_addr: str
    type: str
    from_func: str | None = None


class CodeMatch(BaseModel):
    """Semantic search result."""
    function: str
    code: str
    score: float


class StringXref(BaseModel):
    """String with references."""
    value: str
    address: str
    refs: list[str] = []  # function names that use this string


class BytesResult(BaseModel):
    """Raw bytes."""
    address: str
    hex: str

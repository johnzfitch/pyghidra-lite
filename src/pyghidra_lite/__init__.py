"""pyghidra-lite: Lightweight MCP server for reverse engineering."""

__version__ = "0.6.0"

from pyghidra_lite.analyzer import GhidraAnalyzer
from pyghidra_lite.backend import GhidraBackend
from pyghidra_lite.formats import ElfTools, MachOTools
from pyghidra_lite.lang import ObjCTools, SwiftTools, demangle_swift
from pyghidra_lite.models import AnalysisProfile
from pyghidra_lite.tools import GhidraTools

__all__ = [
    "GhidraAnalyzer",
    "GhidraBackend",
    "GhidraTools",
    "AnalysisProfile",
    "SwiftTools",
    "MachOTools",
    "ObjCTools",
    "ElfTools",
    "demangle_swift",
]

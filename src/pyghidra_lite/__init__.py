"""pyghidra-lite: Lightweight MCP server for reverse engineering."""

__version__ = "0.3.0"

from pyghidra_lite.backend import GhidraBackend
from pyghidra_lite.elf import ElfTools
from pyghidra_lite.macho import MachOTools
from pyghidra_lite.objc import ObjCTools
from pyghidra_lite.swift import SwiftTools, demangle_swift
from pyghidra_lite.tools import GhidraTools

__all__ = [
    "GhidraBackend",
    "GhidraTools",
    "SwiftTools",
    "MachOTools",
    "ObjCTools",
    "ElfTools",
    "demangle_swift",
]

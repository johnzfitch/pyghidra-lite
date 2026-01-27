"""Mach-O specific analysis tools for pyghidra-lite."""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)

# Mach-O load commands
LOAD_COMMANDS = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0x4: "LC_THREAD",
    0x5: "LC_UNIXTHREAD",
    0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER",
    0x19: "LC_SEGMENT_64",
    0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO",
    0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS",
    0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT",
    0x28: "LC_MAIN",
    0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION",
    0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x2D: "LC_LINKER_OPTION",
    0x2E: "LC_LINKER_OPTIMIZATION_HINT",
    0x2F: "LC_VERSION_MIN_TVOS",
    0x30: "LC_VERSION_MIN_WATCHOS",
    0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE",
    0x34: "LC_DYLD_CHAINED_FIXUPS",
    0x80000022: "LC_DYLD_INFO_ONLY",
}

# CPU types
CPU_TYPES = {
    7: "x86",
    12: "arm",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
}

# File types
FILE_TYPES = {
    1: "MH_OBJECT",
    2: "MH_EXECUTE",
    3: "MH_FVMLIB",
    4: "MH_CORE",
    5: "MH_PRELOAD",
    6: "MH_DYLIB",
    7: "MH_DYLINKER",
    8: "MH_BUNDLE",
    9: "MH_DYLIB_STUB",
    10: "MH_DSYM",
    11: "MH_KEXT_BUNDLE",
}


@dataclass
class MachOSegment:
    """Mach-O segment information."""
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    sections: list["MachOSection"] = field(default_factory=list)


@dataclass
class MachOSection:
    """Mach-O section information."""
    name: str
    segment: str
    addr: int
    size: int
    offset: int
    flags: int


@dataclass
class MachODylib:
    """Linked dynamic library."""
    name: str
    current_version: str | None = None
    compat_version: str | None = None
    timestamp: int | None = None


@dataclass
class MachOInfo:
    """Summary of Mach-O binary structure."""
    is_macho: bool
    is_fat: bool = False
    cpu_type: str | None = None
    file_type: str | None = None
    num_segments: int = 0
    num_sections: int = 0
    num_dylibs: int = 0
    has_code_signature: bool = False
    has_encryption: bool = False
    min_os_version: str | None = None
    sdk_version: str | None = None
    entrypoint: str | None = None


class MachOTools:
    """Mach-O specific analysis tools."""

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program

    def is_macho(self) -> bool:
        """Check if binary is Mach-O format."""
        fmt = self.handle.metadata.get("Executable Format", "")
        return "Mach-O" in fmt or "Mac OS X" in fmt

    def get_macho_info(self) -> MachOInfo:
        """Get Mach-O binary structure summary."""
        if not self.is_macho():
            return MachOInfo(is_macho=False)

        metadata = self.handle.metadata

        # Parse CPU type
        cpu_type = None
        processor = metadata.get("Processor", "")
        if "x86" in processor.lower() and "64" in processor:
            cpu_type = "x86_64"
        elif "x86" in processor.lower():
            cpu_type = "x86"
        elif "aarch64" in processor.lower() or "arm64" in processor.lower():
            cpu_type = "arm64"
        elif "arm" in processor.lower():
            cpu_type = "arm"

        # Count segments and sections
        segments = self.list_segments()
        num_sections = sum(len(s.sections) for s in segments)

        # Count dylibs
        dylibs = self.list_dylibs()

        # Check for code signature and encryption
        has_sig = any("__LINKEDIT" in s.name for s in segments)
        has_encryption = any(
            sec.name == "__TEXT.__text" and sec.flags & 0x800
            for s in segments for sec in s.sections
        )

        # Get entrypoint
        entrypoint = None
        fm = self.program.getFunctionManager()
        for func in fm.getFunctions(True):
            if func.getName() in ("_main", "main", "start", "_start", "entry"):
                entrypoint = str(func.getEntryPoint())
                break

        return MachOInfo(
            is_macho=True,
            cpu_type=cpu_type,
            num_segments=len(segments),
            num_sections=num_sections,
            num_dylibs=len(dylibs),
            has_code_signature=has_sig,
            has_encryption=has_encryption,
            entrypoint=entrypoint,
        )

    def list_segments(self) -> list[MachOSegment]:
        """List Mach-O segments and their sections."""
        mem = self.program.getMemory()
        segments = {}

        for block in mem.getBlocks():
            name = block.getName()

            # Parse segment.section format
            if "." in name:
                seg_name, sec_name = name.split(".", 1)
            else:
                seg_name = name
                sec_name = None

            # Get or create segment
            if seg_name not in segments:
                # Compute initprot from individual permission checks
                initprot = 0
                if block.isRead():
                    initprot |= 1
                if block.isWrite():
                    initprot |= 2
                if block.isExecute():
                    initprot |= 4

                segments[seg_name] = MachOSegment(
                    name=seg_name,
                    vmaddr=int(block.getStart().getOffset()),
                    vmsize=0,
                    fileoff=0,
                    filesize=0,
                    maxprot=7,  # rwx
                    initprot=initprot,
                )

            seg = segments[seg_name]
            seg.vmsize += int(block.getSize())

            # Add section
            if sec_name:
                seg.sections.append(MachOSection(
                    name=sec_name,
                    segment=seg_name,
                    addr=int(block.getStart().getOffset()),
                    size=int(block.getSize()),
                    offset=0,
                    flags=0,
                ))

        return list(segments.values())

    def list_sections(self) -> list[MachOSection]:
        """List all Mach-O sections."""
        sections = []
        for seg in self.list_segments():
            sections.extend(seg.sections)
        return sections

    def list_dylibs(self) -> list[MachODylib]:
        """List linked dynamic libraries."""
        st = self.program.getSymbolTable()
        dylibs = set()

        # Find external libraries from imports
        for sym in st.getExternalSymbols():
            lib = str(sym.getParentNamespace())
            if lib and lib != "EXTERNAL":
                dylibs.add(lib)

        return [MachODylib(name=lib) for lib in sorted(dylibs)]

    def get_section(self, name: str) -> MachOSection | None:
        """Get a specific section by name (e.g., '__TEXT.__text')."""
        for section in self.list_sections():
            full_name = f"__{section.segment}.{section.name}"
            if name in (section.name, full_name, f"__{section.segment}.__{section.name}"):
                return section
        return None

    def read_section(self, name: str) -> bytes | None:
        """Read raw bytes from a section."""
        section = self.get_section(name)
        if not section:
            return None

        mem = self.program.getMemory()
        addr = self.program.getAddressFactory().getAddress(hex(section.addr))

        from jpype import JByte
        buf = JByte[section.size]
        n = mem.getBytes(addr, buf)

        if n > 0:
            return bytes([b & 0xFF for b in buf[:n]])
        return None

    def get_entrypoint(self) -> str | None:
        """Get the binary's entrypoint address."""
        fm = self.program.getFunctionManager()
        for func in fm.getFunctions(True):
            if func.getName() in ("_main", "main", "start", "_start", "entry"):
                return str(func.getEntryPoint())

        # Try to find LC_MAIN entrypoint
        # This would require parsing the header directly
        return None

    def list_function_starts(self) -> list[str]:
        """List function start addresses from LC_FUNCTION_STARTS."""
        fm = self.program.getFunctionManager()
        return [str(f.getEntryPoint()) for f in fm.getFunctions(True)]

    def get_code_signature_info(self) -> dict | None:
        """Get code signature information if present."""
        # Look for __LINKEDIT segment
        linkedit = None
        for seg in self.list_segments():
            if seg.name == "__LINKEDIT":
                linkedit = seg
                break

        if not linkedit:
            return None

        return {
            "segment": "__LINKEDIT",
            "vmaddr": hex(linkedit.vmaddr),
            "vmsize": linkedit.vmsize,
            "note": "Code signature data present (detailed parsing not implemented)",
        }

"""ELF and Mach-O format inspection tools for pyghidra-lite."""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)


# =============================================================================
# ELF
# =============================================================================

# ELF section types
ELF_SECTION_TYPES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
}


@dataclass
class ElfSection:
    """ELF section information."""
    name: str
    type: str
    addr: int
    size: int
    flags: list[str] = field(default_factory=list)


@dataclass
class ElfSymbol:
    """ELF symbol information."""
    name: str
    addr: int
    size: int
    type: str  # FUNC, OBJECT, NOTYPE, etc.
    bind: str  # LOCAL, GLOBAL, WEAK
    section: str | None = None


@dataclass
class ElfDynamic:
    """ELF dynamic entry."""
    tag: str
    value: str


@dataclass
class ElfRelocation:
    """ELF relocation entry."""
    offset: int
    type: str
    symbol: str
    addend: int | None = None


@dataclass
class ElfInfo:
    """Summary of ELF binary structure."""
    is_elf: bool
    bits: int | None = None
    endian: str | None = None
    machine: str | None = None
    type: str | None = None
    num_sections: int = 0
    num_symbols: int = 0
    has_debug: bool = False
    is_stripped: bool = True
    interpreter: str | None = None


class ElfTools:
    """ELF format inspection tools."""

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program

    def is_elf(self) -> bool:
        """Check if binary is ELF format."""
        fmt = self.handle.metadata.get("Executable Format", "")
        return "ELF" in fmt

    def get_elf_info(self) -> ElfInfo:
        """Get ELF binary structure summary."""
        if not self.is_elf():
            return ElfInfo(is_elf=False)

        metadata = self.handle.metadata

        bits = None
        addr_size = metadata.get("Address Size", "")
        if "64" in addr_size:
            bits = 64
        elif "32" in addr_size:
            bits = 32

        endian = metadata.get("Endian", "").lower()
        if "little" in endian:
            endian = "little"
        elif "big" in endian:
            endian = "big"
        else:
            endian = None

        machine = metadata.get("Processor", "")
        sections = self.list_sections()
        has_debug = any(s.name.startswith(".debug") for s in sections)
        is_stripped = not any(s.name == ".symtab" for s in sections)

        num_symbols = 0
        st = self.program.getSymbolTable()
        for _ in st.getAllSymbols(True):
            num_symbols += 1
            if num_symbols > 10000:
                break

        return ElfInfo(
            is_elf=True,
            bits=bits,
            endian=endian,
            machine=machine,
            num_sections=len(sections),
            num_symbols=num_symbols,
            has_debug=has_debug,
            is_stripped=is_stripped,
        )

    def list_sections(self) -> list[ElfSection]:
        """List ELF sections."""
        mem = self.program.getMemory()
        sections = []

        for block in mem.getBlocks():
            name = block.getName()

            flags = []
            if block.isWrite():
                flags.append("WRITE")
            if block.isExecute():
                flags.append("EXEC")
            if block.isInitialized():
                flags.append("ALLOC")

            sec_type = "PROGBITS"
            if name == ".bss" or not block.isInitialized():
                sec_type = "NOBITS"
            elif name == ".symtab":
                sec_type = "SYMTAB"
            elif name == ".dynsym":
                sec_type = "DYNSYM"
            elif name in (".strtab", ".dynstr"):
                sec_type = "STRTAB"
            elif name.startswith(".rela"):
                sec_type = "RELA"
            elif name.startswith(".rel"):
                sec_type = "REL"
            elif name == ".dynamic":
                sec_type = "DYNAMIC"
            elif name.startswith(".note"):
                sec_type = "NOTE"
            elif name == ".init_array":
                sec_type = "INIT_ARRAY"
            elif name == ".fini_array":
                sec_type = "FINI_ARRAY"

            sections.append(ElfSection(
                name=name,
                type=sec_type,
                addr=int(block.getStart().getOffset()),
                size=int(block.getSize()),
                flags=flags,
            ))

        return sections

    def get_section(self, name: str) -> ElfSection | None:
        """Get a specific section by name."""
        for section in self.list_sections():
            if section.name == name:
                return section
        return None

    def list_symbols(self, pattern: str = "", limit: int = 50) -> list[ElfSymbol]:
        """List ELF symbols."""
        st = self.program.getSymbolTable()
        fm = self.program.getFunctionManager()
        symbols = []

        for sym in st.getAllSymbols(True):
            name = sym.getName()
            if pattern and pattern.lower() not in name.lower():
                continue

            sym_type = str(sym.getSymbolType())
            if sym_type == "Function":
                sym_type = "FUNC"
            elif sym_type == "Label":
                sym_type = "NOTYPE"
            else:
                sym_type = "OBJECT"

            bind = "GLOBAL"
            if sym.getParentNamespace().getName() != "Global":
                bind = "LOCAL"

            size = 0
            func = fm.getFunctionAt(sym.getAddress())
            if func:
                size = int(func.getBody().getNumAddresses())

            symbols.append(ElfSymbol(
                name=name,
                addr=int(sym.getAddress().getOffset()),
                size=size,
                type=sym_type,
                bind=bind,
            ))

            if len(symbols) >= limit:
                break

        return symbols

    def list_dynamic(self) -> list[ElfDynamic]:
        """List dynamic section entries (NEEDED libs, etc)."""
        st = self.program.getSymbolTable()
        libs = set()

        for sym in st.getExternalSymbols():
            lib = str(sym.getParentNamespace())
            if lib and lib != "EXTERNAL":
                libs.add(lib)

        return [ElfDynamic(tag="NEEDED", value=lib) for lib in sorted(libs)]

    def get_got_plt(self) -> list[dict]:
        """Get GOT/PLT entries."""
        results = []

        got_section = self.get_section(".got.plt") or self.get_section(".got")
        plt_section = self.get_section(".plt")

        if got_section:
            results.append({
                "section": ".got",
                "addr": hex(got_section.addr),
                "size": got_section.size,
            })
        if plt_section:
            results.append({
                "section": ".plt",
                "addr": hex(plt_section.addr),
                "size": plt_section.size,
            })

        fm = self.program.getFunctionManager()
        for func in fm.getFunctions(True):
            if func.isThunk():
                thunked = func.getThunkedFunction(True)
                if thunked and thunked.isExternal():
                    results.append({
                        "type": "PLT",
                        "name": func.getName(),
                        "addr": str(func.getEntryPoint()),
                        "target": thunked.getName(),
                    })

        return results


# =============================================================================
# MACH-O
# =============================================================================

# Mach-O load commands (reference)
MACHO_LOAD_COMMANDS = {
    0x1: "LC_SEGMENT",
    0x19: "LC_SEGMENT_64",
    0xC: "LC_LOAD_DYLIB",
    0x1D: "LC_CODE_SIGNATURE",
    0x28: "LC_MAIN",
    0x32: "LC_BUILD_VERSION",
    0x80000022: "LC_DYLD_INFO_ONLY",
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


@dataclass
class MachOInfo:
    """Summary of Mach-O binary structure."""
    is_macho: bool
    cpu_type: str | None = None
    file_type: str | None = None
    num_segments: int = 0
    num_sections: int = 0
    num_dylibs: int = 0
    has_code_signature: bool = False
    has_encryption: bool = False
    entrypoint: str | None = None


class MachOTools:
    """Mach-O format inspection tools."""

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
        processor = metadata.get("Processor", "").lower()

        cpu_type = None
        if "x86" in processor and "64" in processor:
            cpu_type = "x86_64"
        elif "x86" in processor:
            cpu_type = "x86"
        elif "aarch64" in processor or "arm64" in processor:
            cpu_type = "arm64"
        elif "arm" in processor:
            cpu_type = "arm"

        segments = self.list_segments()
        num_sections = sum(len(s.sections) for s in segments)
        dylibs = self.list_dylibs()

        has_sig = any("__LINKEDIT" in s.name for s in segments)
        has_encryption = any(
            sec.name == "__TEXT.__text" and sec.flags & 0x800
            for s in segments for sec in s.sections
        )

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

            if "." in name:
                seg_name, sec_name = name.split(".", 1)
            else:
                seg_name = name
                sec_name = None

            if seg_name not in segments:
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
                    maxprot=7,
                    initprot=initprot,
                )

            seg = segments[seg_name]
            seg.vmsize += int(block.getSize())

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

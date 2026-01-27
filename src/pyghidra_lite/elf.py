"""ELF-specific analysis tools for pyghidra-lite."""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)

# ELF section types
SECTION_TYPES = {
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

# ELF section flags
SECTION_FLAGS = {
    0x1: "WRITE",
    0x2: "ALLOC",
    0x4: "EXECINSTR",
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
class ElfRelocation:
    """ELF relocation entry."""
    offset: int
    type: str
    symbol: str
    addend: int | None = None


@dataclass
class ElfDynamic:
    """ELF dynamic entry."""
    tag: str
    value: str


@dataclass
class ElfInfo:
    """Summary of ELF binary structure."""
    is_elf: bool
    bits: int | None = None  # 32 or 64
    endian: str | None = None  # little or big
    machine: str | None = None  # x86_64, ARM, etc.
    type: str | None = None  # EXEC, DYN, REL
    num_sections: int = 0
    num_symbols: int = 0
    has_debug: bool = False
    is_stripped: bool = True
    interpreter: str | None = None  # /lib64/ld-linux-x86-64.so.2


class ElfTools:
    """ELF-specific analysis tools."""

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

        # Parse bits
        bits = None
        addr_size = metadata.get("Address Size", "")
        if "64" in addr_size:
            bits = 64
        elif "32" in addr_size:
            bits = 32

        # Parse endianness
        endian = metadata.get("Endian", "").lower()
        if "little" in endian:
            endian = "little"
        elif "big" in endian:
            endian = "big"
        else:
            endian = None

        # Parse machine type
        machine = metadata.get("Processor", "")

        # Count sections
        sections = self.list_sections()

        # Check for debug info
        has_debug = any(s.name.startswith(".debug") for s in sections)

        # Check if stripped (no .symtab section usually means stripped)
        is_stripped = not any(s.name == ".symtab" for s in sections)

        # Count symbols
        num_symbols = 0
        st = self.program.getSymbolTable()
        for _ in st.getAllSymbols(True):
            num_symbols += 1
            if num_symbols > 10000:  # Cap counting
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

            # Parse flags from block permissions
            flags = []
            if block.isWrite():
                flags.append("WRITE")
            if block.isExecute():
                flags.append("EXEC")
            if block.isInitialized():
                flags.append("ALLOC")

            # Determine type
            sec_type = "PROGBITS"
            if name == ".bss" or not block.isInitialized():
                sec_type = "NOBITS"
            elif name == ".symtab":
                sec_type = "SYMTAB"
            elif name == ".dynsym":
                sec_type = "DYNSYM"
            elif name == ".strtab" or name == ".dynstr":
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
        """List ELF symbols.

        Args:
            pattern: Filter by name substring
            limit: Max results (default 50)
        """
        st = self.program.getSymbolTable()
        fm = self.program.getFunctionManager()
        symbols = []

        for sym in st.getAllSymbols(True):
            name = sym.getName()

            if pattern and pattern.lower() not in name.lower():
                continue

            addr = int(sym.getAddress().getOffset())

            # Determine type
            sym_type = str(sym.getSymbolType())
            if sym_type == "Function":
                sym_type = "FUNC"
            elif sym_type == "Label":
                sym_type = "NOTYPE"
            else:
                sym_type = "OBJECT"

            # Determine binding (approximation)
            bind = "GLOBAL"
            if sym.getParentNamespace().getName() != "Global":
                bind = "LOCAL"

            # Get size for functions
            size = 0
            func = fm.getFunctionAt(sym.getAddress())
            if func:
                size = int(func.getBody().getNumAddresses())

            symbols.append(ElfSymbol(
                name=name,
                addr=addr,
                size=size,
                type=sym_type,
                bind=bind,
            ))

            if len(symbols) >= limit:
                break

        return symbols

    def list_dynamic(self) -> list[ElfDynamic]:
        """List dynamic section entries (NEEDED libs, etc)."""
        # This is approximated from external symbols
        st = self.program.getSymbolTable()
        libs = set()

        for sym in st.getExternalSymbols():
            lib = str(sym.getParentNamespace())
            if lib and lib != "EXTERNAL":
                libs.add(lib)

        entries = []
        for lib in sorted(libs):
            entries.append(ElfDynamic(tag="NEEDED", value=lib))

        return entries

    def list_relocations(self, limit: int = 100) -> list[ElfRelocation]:
        """List relocations (GOT/PLT entries)."""
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        st = self.program.getSymbolTable()
        relocations = []

        # Find external references (these are typically relocations)
        for sym in st.getExternalSymbols():
            for ref in rm.getReferencesTo(sym.getAddress()):
                relocations.append(ElfRelocation(
                    offset=int(ref.getFromAddress().getOffset()),
                    type="R_X86_64_PLT32" if fm.getFunctionContaining(ref.getFromAddress()) else "R_X86_64_GLOB_DAT",
                    symbol=sym.getName(),
                ))

                if len(relocations) >= limit:
                    return relocations

        return relocations

    def get_got_plt(self) -> list[dict]:
        """Get GOT/PLT entries."""
        results = []

        # Find .got.plt or .plt sections
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

        # List PLT entries (thunk functions)
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

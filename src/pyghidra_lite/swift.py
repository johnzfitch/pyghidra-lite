"""Swift-specific analysis tools for pyghidra-lite."""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)

# Swift mangled name prefix
SWIFT_MANGLED_PREFIX = ("_$s", "$s", "_$S", "$S", "_T0", "_T")

# Swift metadata sections (Mach-O)
SWIFT_SECTIONS = {
    "__swift5_types": "Type descriptors",
    "__swift5_proto": "Protocol conformances",
    "__swift5_protos": "Protocol descriptors",
    "__swift5_fieldmd": "Field metadata",
    "__swift5_assocty": "Associated type metadata",
    "__swift5_builtin": "Builtin type metadata",
    "__swift5_reflstr": "Reflection strings",
    "__swift5_typeref": "Type references",
    "__swift5_capture": "Capture descriptors",
    "__swift5_mpenum": "Multi-payload enum descriptors",
}


@dataclass
class SwiftSymbol:
    """A demangled Swift symbol."""
    mangled: str
    demangled: str
    address: str
    kind: str | None = None  # function, type, protocol, etc.
    module: str | None = None
    type_name: str | None = None


@dataclass
class SwiftType:
    """Swift type information extracted from metadata."""
    name: str
    module: str | None = None
    kind: str | None = None  # struct, class, enum, protocol
    fields: list[tuple[str, str]] = field(default_factory=list)  # (name, type)
    protocols: list[str] = field(default_factory=list)
    address: str | None = None


@dataclass
class SwiftInfo:
    """Summary of Swift content in a binary."""
    is_swift: bool
    swift_version: str | None = None
    module_name: str | None = None
    num_types: int = 0
    num_protocols: int = 0
    num_swift_functions: int = 0
    sections: dict[str, int] = field(default_factory=dict)  # section -> size


def is_swift_mangled(name: str) -> bool:
    """Check if a symbol name is Swift-mangled."""
    return any(name.startswith(prefix) for prefix in SWIFT_MANGLED_PREFIX)


def demangle_swift(mangled: str) -> str:
    """Demangle a Swift symbol name.

    Tries swift-demangle tool first, falls back to basic parsing.
    Handles all subprocess errors gracefully.
    """
    if not is_swift_mangled(mangled):
        return mangled

    # Try swift-demangle tool
    try:
        result = subprocess.run(
            ["swift-demangle", "-compact", mangled],
            capture_output=True,
            text=True,
            timeout=1,
        )
        if result.returncode == 0 and result.stdout.strip():
            demangled = result.stdout.strip()
            if demangled != mangled:
                return demangled
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
        logger.debug("swift-demangle failed: %s", e)

    # Try xcrun swift-demangle (macOS)
    try:
        result = subprocess.run(
            ["xcrun", "swift-demangle", "-compact", mangled],
            capture_output=True,
            text=True,
            timeout=1,
        )
        if result.returncode == 0 and result.stdout.strip():
            demangled = result.stdout.strip()
            if demangled != mangled:
                return demangled
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
        logger.debug("xcrun swift-demangle failed: %s", e)

    # Fallback: basic parsing
    return _basic_demangle(mangled)


def _basic_demangle(mangled: str) -> str:
    """Basic Swift demangling without external tools.

    This handles common patterns but isn't complete.
    """
    # Remove prefix
    name = mangled
    for prefix in SWIFT_MANGLED_PREFIX:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    # Try to extract readable parts
    # Swift uses length-prefixed strings: 4main -> "main"
    parts = []
    i = 0
    while i < len(name):
        # Check for length prefix
        length_match = re.match(r'^(\d+)', name[i:])
        if length_match:
            length = int(length_match.group(1))
            i += len(length_match.group(1))
            if i + length <= len(name):
                parts.append(name[i:i+length])
                i += length
                continue

        # Check for known suffixes
        if name[i:].startswith('C') or name[i:].startswith('V') or name[i:].startswith('O') or name[i:].startswith('F') or name[i:].startswith('S'):  # Class
            i += 1
            continue

        i += 1

    if parts:
        return ".".join(parts)

    return mangled  # Give up, return original


def demangle_batch(names: list[str]) -> dict[str, str]:
    """Demangle multiple Swift names efficiently.

    Uses batch mode with swift-demangle for better performance.
    Falls back to basic demangling on any subprocess error.
    """
    swift_names = [n for n in names if is_swift_mangled(n)]
    if not swift_names:
        return {n: n for n in names}

    results = {n: n for n in names}

    # Try batch demangling with swift-demangle
    try:
        input_text = "\n".join(swift_names)
        result = subprocess.run(
            ["swift-demangle", "-compact"],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=max(5, len(swift_names) // 100),  # Scale timeout with input size
        )
        if result.returncode == 0:
            demangled_lines = result.stdout.strip().split("\n")
            # Use zip without strict since output lines may differ from input
            for mangled, demangled in zip(swift_names, demangled_lines, strict=False):
                if demangled and demangled != mangled:
                    results[mangled] = demangled
            return results

    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
        logger.debug("Batch demangle failed, using fallback: %s", e)

    # Fall back to basic demangling (no external process)
    for name in swift_names:
        results[name] = _basic_demangle(name)

    return results


def extract_module_name(demangled: str) -> str | None:
    """Extract module name from demangled Swift symbol."""
    # Format is typically: Module.Type.method or Module.function
    if "." in demangled:
        return demangled.split(".")[0]
    return None


def classify_swift_symbol(mangled: str, demangled: str) -> str:
    """Classify a Swift symbol by its type."""
    # Check mangled prefixes
    name = mangled
    for prefix in ("_$s", "$s", "_$S", "$S"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    # Look for type indicators in mangled name
    if "C" in mangled and "init" in demangled.lower():
        return "initializer"
    elif "getter" in demangled.lower() or "fG" in mangled:
        return "getter"
    elif "setter" in demangled.lower() or "fS" in mangled:
        return "setter"
    elif "subscript" in demangled.lower():
        return "subscript"
    elif ".init" in demangled or "init(" in demangled:
        return "initializer"
    elif ".deinit" in demangled:
        return "deinitializer"
    elif "witness" in demangled.lower() or "WV" in mangled or "Wl" in mangled:
        return "witness"
    elif "protocol" in demangled.lower():
        return "protocol"
    elif "metadata" in demangled.lower() or "Ma" in mangled or "Mn" in mangled:
        return "metadata"
    elif "(" in demangled and ")" in demangled:
        return "function"
    elif demangled[0].isupper() if demangled else False:
        return "type"

    return "unknown"


class SwiftTools:
    """Swift-specific analysis tools for a loaded binary."""

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program
        self._demangle_cache: dict[str, str] = {}

    def is_swift_binary(self) -> bool:
        """Check if the binary contains Swift code."""
        # Check for Swift sections
        mem = self.program.getMemory()
        for block in mem.getBlocks():
            name = block.getName()
            if any(s in name for s in SWIFT_SECTIONS):
                return True

        # Check for Swift symbols
        st = self.program.getSymbolTable()
        count = 0
        for sym in st.getAllSymbols(True):
            if is_swift_mangled(sym.getName()):
                count += 1
                if count > 5:
                    return True

        return False

    def get_swift_info(self) -> SwiftInfo:
        """Get summary of Swift content in the binary.

        Uses batch demangling for efficiency when processing many symbols.
        """
        mem = self.program.getMemory()
        st = self.program.getSymbolTable()

        # Find Swift sections
        sections = {}
        for block in mem.getBlocks():
            name = block.getName()
            for swift_section in SWIFT_SECTIONS:
                if swift_section in name:
                    sections[swift_section] = int(block.getSize())

        # Collect all Swift symbol names first for batch demangling
        swift_names = []
        for sym in st.getAllSymbols(True):
            name = sym.getName()
            if is_swift_mangled(name):
                swift_names.append(name)

        # Batch demangle all at once (much faster than individual calls)
        demangled_map = demangle_batch(swift_names) if swift_names else {}

        # Update cache with batch results
        self._demangle_cache.update(demangled_map)

        # Extract modules from demangled names
        modules: dict[str, int] = {}
        for mangled in swift_names:
            demangled = demangled_map.get(mangled, mangled)
            module = extract_module_name(demangled)
            if module:
                modules[module] = modules.get(module, 0) + 1

        # Determine primary module (most common user module)
        module_name = None
        if modules:
            # Filter out standard library modules
            user_modules = {m: c for m, c in modules.items()
                          if m not in ("Swift", "Foundation", "Darwin", "ObjectiveC", "_")}
            if user_modules:
                module_name = max(user_modules.keys(), key=lambda m: user_modules[m])

        return SwiftInfo(
            is_swift=bool(sections) or len(swift_names) > 0,
            module_name=module_name,
            num_swift_functions=len(swift_names),
            sections=sections,
        )

    def demangle(self, name: str) -> str:
        """Demangle a Swift symbol (cached)."""
        if name in self._demangle_cache:
            return self._demangle_cache[name]

        result = demangle_swift(name)
        self._demangle_cache[name] = result
        return result

    def list_swift_functions(
        self,
        pattern: str = "",
        limit: int = 50,
        kind: str | None = None,
        demangled: bool = True,
    ) -> list[SwiftSymbol]:
        """List Swift functions with demangled names.

        Args:
            pattern: Filter by demangled name substring
            limit: Max results
            kind: Filter by kind (function, initializer, getter, etc.)
            demangled: If True, match pattern against demangled names
        """
        fm = self.program.getFunctionManager()
        results = []

        # Collect all Swift functions first for batch demangling
        swift_funcs = []
        for func in fm.getFunctions(True):
            name = func.getName()
            if is_swift_mangled(name):
                swift_funcs.append((func, name))

        # Batch demangle
        mangled_names = [n for _, n in swift_funcs]
        demangled_map = demangle_batch(mangled_names)

        for func, mangled in swift_funcs:
            demangled_name = demangled_map.get(mangled, mangled)

            # Filter by pattern
            search_name = demangled_name if demangled else mangled
            if pattern and pattern.lower() not in search_name.lower():
                continue

            # Classify
            sym_kind = classify_swift_symbol(mangled, demangled_name)

            # Filter by kind
            if kind and sym_kind != kind:
                continue

            module = extract_module_name(demangled_name)

            results.append(SwiftSymbol(
                mangled=mangled,
                demangled=demangled_name,
                address=str(func.getEntryPoint()),
                kind=sym_kind,
                module=module,
            ))

            if len(results) >= limit:
                break

        return results

    def list_swift_types(self, limit: int = 50) -> list[SwiftType]:
        """Extract Swift types from metadata sections.

        Note: This provides basic type discovery. Full metadata parsing
        requires more sophisticated analysis of __swift5_types section.
        """
        st = self.program.getSymbolTable()
        types = {}

        # Find type metadata symbols
        for sym in st.getAllSymbols(True):
            name = sym.getName()
            if not is_swift_mangled(name):
                continue

            demangled = self.demangle(name)

            # Look for type metadata accessors
            if "type metadata accessor" in demangled.lower():
                # Extract type name
                match = re.search(r"type metadata accessor for (.+)", demangled)
                if match:
                    type_name = match.group(1)
                    if type_name not in types:
                        module = extract_module_name(type_name)
                        types[type_name] = SwiftType(
                            name=type_name.split(".")[-1] if "." in type_name else type_name,
                            module=module,
                            address=str(sym.getAddress()),
                        )

            # Look for nominal type descriptors
            elif "nominal type descriptor" in demangled.lower():
                match = re.search(r"nominal type descriptor for (.+)", demangled)
                if match:
                    type_name = match.group(1)
                    if type_name not in types:
                        module = extract_module_name(type_name)
                        # Determine kind from context
                        kind = None
                        if "struct" in demangled.lower():
                            kind = "struct"
                        elif "class" in demangled.lower():
                            kind = "class"
                        elif "enum" in demangled.lower():
                            kind = "enum"

                        types[type_name] = SwiftType(
                            name=type_name.split(".")[-1] if "." in type_name else type_name,
                            module=module,
                            kind=kind,
                            address=str(sym.getAddress()),
                        )

            if len(types) >= limit:
                break

        return list(types.values())[:limit]

    def find_swift_strings(self, limit: int = 50) -> list[tuple[str, str, list[str]]]:
        """Find strings used in Swift code with their referencing functions.

        Returns list of (string_value, address, [referencing_swift_functions])
        """
        from pyghidra_lite.tools import GhidraTools
        tools = GhidraTools(self.handle)

        results = []
        for string_info in tools.search_strings("", limit=limit * 2):
            # Check if referenced by Swift functions
            swift_refs = []
            for ref_func in (string_info.refs or []):
                if is_swift_mangled(ref_func):
                    swift_refs.append(self.demangle(ref_func))
                elif any(is_swift_mangled(ref_func) for ref_func in (string_info.refs or [])):
                    swift_refs.append(ref_func)

            if swift_refs:
                results.append((string_info.value, string_info.address, swift_refs))
                if len(results) >= limit:
                    break

        return results

    def decompile_swift(self, function: str, timeout: int = 30) -> dict:
        """Decompile a Swift function with enhanced metadata.

        Args:
            function: Function name (mangled or demangled) or address

        Returns:
            Dict with decompiled code and Swift-specific info
        """
        from pyghidra_lite.tools import GhidraTools
        tools = GhidraTools(self.handle)

        # Find the function
        fm = self.program.getFunctionManager()
        target_func = None

        # Try as address first
        if function.startswith("0x") or function.startswith("0X"):
            try:
                addr = self.program.getAddressFactory().getAddress(function.replace("0x", ""))
                target_func = fm.getFunctionAt(addr)
            except Exception:
                pass

        if not target_func:
            # Search by name (mangled or demangled)
            function_lower = function.lower()
            for func in fm.getFunctions(True):
                name = func.getName()
                if name == function or name.lower() == function_lower:
                    target_func = func
                    break
                # Also check demangled
                if is_swift_mangled(name):
                    demangled = self.demangle(name)
                    if function in demangled or function_lower in demangled.lower():
                        target_func = func
                        break

        if not target_func:
            raise ValueError(f"Swift function not found: {function}")

        mangled_name = target_func.getName()
        demangled_name = self.demangle(mangled_name) if is_swift_mangled(mangled_name) else mangled_name

        # Decompile
        result = tools.decompile_function(mangled_name, timeout=timeout)

        # Get callees with demangling
        callees_raw = tools.get_callees(mangled_name)
        callees_demangled = []
        for callee in callees_raw:
            if is_swift_mangled(callee):
                callees_demangled.append({
                    "mangled": callee,
                    "demangled": self.demangle(callee),
                    "kind": classify_swift_symbol(callee, self.demangle(callee)),
                })
            else:
                callees_demangled.append({"name": callee})

        return {
            "mangled": mangled_name,
            "demangled": demangled_name,
            "kind": classify_swift_symbol(mangled_name, demangled_name),
            "module": extract_module_name(demangled_name),
            "address": str(target_func.getEntryPoint()),
            "code": result.code,
            "signature": result.signature,
            "callees": callees_demangled,
            "strings": result.strings_used,
        }

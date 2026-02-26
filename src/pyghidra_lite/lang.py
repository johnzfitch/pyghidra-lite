"""Swift and Objective-C language analysis tools for pyghidra-lite."""

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


# =============================================================================
# OBJECTIVE-C
# =============================================================================

# ObjC method type prefixes
OBJC_METHOD_TYPES = {
    "+": "class_method",
    "-": "instance_method",
}

# Common ObjC frameworks
OBJC_FRAMEWORKS = {
    "NSObject": "Foundation",
    "NSString": "Foundation",
    "NSArray": "Foundation",
    "NSDictionary": "Foundation",
    "NSData": "Foundation",
    "NSURL": "Foundation",
    "NSError": "Foundation",
    "NSNotification": "Foundation",
    "UIView": "UIKit",
    "UIViewController": "UIKit",
    "UIApplication": "UIKit",
    "UIWindow": "UIKit",
    "UIButton": "UIKit",
    "UILabel": "UIKit",
    "UITableView": "UIKit",
    "NSView": "AppKit",
    "NSWindow": "AppKit",
    "NSApplication": "AppKit",
}


@dataclass
class ObjCClass:
    """Objective-C class information."""
    name: str
    superclass: str | None = None
    metaclass: str | None = None
    methods: list["ObjCMethod"] = field(default_factory=list)
    ivars: list["ObjCIvar"] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    properties: list["ObjCProperty"] = field(default_factory=list)
    address: str | None = None
    is_swift: bool = False


@dataclass
class ObjCMethod:
    """Objective-C method information."""
    selector: str
    type_encoding: str | None = None
    impl_address: str | None = None
    is_class_method: bool = False
    class_name: str | None = None

    @property
    def signature(self) -> str:
        """Get full method signature."""
        prefix = "+" if self.is_class_method else "-"
        if self.class_name:
            return f"{prefix}[{self.class_name} {self.selector}]"
        return f"{prefix}{self.selector}"


@dataclass
class ObjCIvar:
    """Objective-C instance variable."""
    name: str
    type_encoding: str | None = None
    offset: int | None = None


@dataclass
class ObjCProperty:
    """Objective-C property."""
    name: str
    attributes: str | None = None
    getter: str | None = None
    setter: str | None = None


@dataclass
class ObjCProtocol:
    """Objective-C protocol information."""
    name: str
    methods: list[ObjCMethod] = field(default_factory=list)
    optional_methods: list[ObjCMethod] = field(default_factory=list)
    properties: list[ObjCProperty] = field(default_factory=list)


@dataclass
class ObjCCategory:
    """Objective-C category information."""
    name: str
    class_name: str
    methods: list[ObjCMethod] = field(default_factory=list)


@dataclass
class ObjCInfo:
    """Summary of Objective-C content in a binary."""
    has_objc: bool
    num_classes: int = 0
    num_categories: int = 0
    num_protocols: int = 0
    num_selectors: int = 0
    has_arc: bool = False  # Automatic Reference Counting
    frameworks: list[str] = field(default_factory=list)


def parse_objc_selector(name: str) -> tuple[str | None, str | None, str]:
    """Parse ObjC selector from function name.

    Returns (class_name, method_type, selector)
    """
    # Pattern: -[ClassName methodName:] or +[ClassName methodName:]
    match = re.match(r'^([+-])\[(\w+)\s+(.+)\]$', name)
    if match:
        method_type = "class_method" if match.group(1) == "+" else "instance_method"
        return match.group(2), method_type, match.group(3)

    # Pattern: _OBJC_CLASS_$_ClassName
    match = re.match(r'^_OBJC_CLASS_\$_(\w+)$', name)
    if match:
        return match.group(1), None, ""

    # Pattern: _OBJC_METACLASS_$_ClassName
    match = re.match(r'^_OBJC_METACLASS_\$_(\w+)$', name)
    if match:
        return match.group(1), "metaclass", ""

    return None, None, name


def is_objc_symbol(name: str) -> bool:
    """Check if a symbol is Objective-C related."""
    objc_patterns = [
        r'^[+-]\[',  # Method signature
        r'^_OBJC_',  # ObjC runtime symbols
        r'^_objc_',  # ObjC runtime functions
        r'@selector\(',  # Selector references
    ]
    return any(re.match(p, name) for p in objc_patterns)


class ObjCTools:
    """Objective-C specific analysis tools."""

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program
        self._class_cache: dict[str, ObjCClass] = {}

    def has_objc(self) -> bool:
        """Check if binary contains Objective-C code."""
        mem = self.program.getMemory()

        # Check for ObjC sections
        for block in mem.getBlocks():
            name = block.getName()
            if any(s in name for s in ["__objc_", "objc_class", "objc_data"]):
                return True

        # Check for ObjC symbols
        st = self.program.getSymbolTable()
        count = 0
        for sym in st.getAllSymbols(True):
            if is_objc_symbol(sym.getName()):
                count += 1
                if count > 3:
                    return True

        return False

    def get_objc_info(self) -> ObjCInfo:
        """Get summary of Objective-C content."""
        st = self.program.getSymbolTable()

        classes = set()
        categories = set()
        protocols = set()
        selectors = set()
        frameworks = set()

        for sym in st.getAllSymbols(True):
            name = sym.getName()

            if name.startswith("_OBJC_CLASS_$_"):
                class_name = name.replace("_OBJC_CLASS_$_", "")
                classes.add(class_name)
                if class_name in OBJC_FRAMEWORKS:
                    frameworks.add(OBJC_FRAMEWORKS[class_name])

            elif name.startswith("_OBJC_METACLASS_$_"):
                pass  # Counted with classes

            elif "_$_category_" in name.lower():
                categories.add(name)

            elif name.startswith("_OBJC_PROTOCOL_$_"):
                protocols.add(name.replace("_OBJC_PROTOCOL_$_", ""))

            elif re.match(r'^[+-]\[', name):
                # Extract selector
                match = re.match(r'^[+-]\[\w+\s+(.+)\]$', name)
                if match:
                    selectors.add(match.group(1))

        # Check for ARC
        has_arc = False
        fm = self.program.getFunctionManager()
        for func in fm.getFunctions(True):
            name = func.getName()
            if "objc_retain" in name or "objc_release" in name or "objc_autoreleaseReturnValue" in name:
                has_arc = True
                break

        return ObjCInfo(
            has_objc=bool(classes) or bool(selectors),
            num_classes=len(classes),
            num_categories=len(categories),
            num_protocols=len(protocols),
            num_selectors=len(selectors),
            has_arc=has_arc,
            frameworks=sorted(frameworks),
        )

    def list_classes(self, pattern: str = "", limit: int = 50) -> list[ObjCClass]:
        """List Objective-C classes.

        Args:
            pattern: Filter by class name substring
            limit: Max results
        """
        st = self.program.getSymbolTable()
        classes = {}

        for sym in st.getAllSymbols(True):
            name = sym.getName()

            # Find class symbols
            if name.startswith("_OBJC_CLASS_$_"):
                class_name = name.replace("_OBJC_CLASS_$_", "")

                if pattern and pattern.lower() not in class_name.lower():
                    continue

                if class_name not in classes:
                    classes[class_name] = ObjCClass(
                        name=class_name,
                        address=str(sym.getAddress()),
                    )

                if len(classes) >= limit:
                    break

        # Try to find methods for each class
        for class_name, cls in classes.items():
            cls.methods = self._find_methods_for_class(class_name, limit=20)

        return list(classes.values())[:limit]

    def _find_methods_for_class(self, class_name: str, limit: int = 50) -> list[ObjCMethod]:
        """Find methods belonging to a class."""
        fm = self.program.getFunctionManager()
        methods = []

        pattern = re.compile(rf'^([+-])\[{re.escape(class_name)}\s+(.+)\]$')

        for func in fm.getFunctions(True):
            name = func.getName()
            match = pattern.match(name)
            if match:
                methods.append(ObjCMethod(
                    selector=match.group(2),
                    is_class_method=(match.group(1) == "+"),
                    class_name=class_name,
                    impl_address=str(func.getEntryPoint()),
                ))

                if len(methods) >= limit:
                    break

        return methods

    def list_methods(
        self,
        pattern: str = "",
        class_name: str | None = None,
        limit: int = 50,
    ) -> list[ObjCMethod]:
        """List Objective-C methods.

        Args:
            pattern: Filter by selector substring
            class_name: Filter by class name
            limit: Max results
        """
        fm = self.program.getFunctionManager()
        methods = []

        method_pattern = re.compile(r'^([+-])\[(\w+)\s+(.+)\]$')

        for func in fm.getFunctions(True):
            name = func.getName()
            match = method_pattern.match(name)
            if not match:
                continue

            cls = match.group(2)
            selector = match.group(3)

            if class_name and cls != class_name:
                continue

            if pattern and pattern.lower() not in selector.lower():
                continue

            methods.append(ObjCMethod(
                selector=selector,
                is_class_method=(match.group(1) == "+"),
                class_name=cls,
                impl_address=str(func.getEntryPoint()),
            ))

            if len(methods) >= limit:
                break

        return methods

    def list_selectors(self, pattern: str = "", limit: int = 50) -> list[str]:
        """List unique Objective-C selectors."""
        selectors = set()

        for method in self.list_methods(pattern=pattern, limit=limit * 2):
            selectors.add(method.selector)
            if len(selectors) >= limit:
                break

        return sorted(selectors)[:limit]

    def list_protocols(self, limit: int = 50) -> list[ObjCProtocol]:
        """List Objective-C protocols."""
        st = self.program.getSymbolTable()
        protocols = []

        for sym in st.getAllSymbols(True):
            name = sym.getName()
            if name.startswith("_OBJC_PROTOCOL_$_"):
                proto_name = name.replace("_OBJC_PROTOCOL_$_", "")
                protocols.append(ObjCProtocol(name=proto_name))

                if len(protocols) >= limit:
                    break

        return protocols

    def get_class(self, name: str) -> ObjCClass | None:
        """Get detailed information about a class."""
        if name in self._class_cache:
            return self._class_cache[name]

        st = self.program.getSymbolTable()

        # Find class symbol
        class_sym = None
        for sym in st.getAllSymbols(True):
            if sym.getName() == f"_OBJC_CLASS_$_{name}":
                class_sym = sym
                break

        if not class_sym:
            return None

        cls = ObjCClass(
            name=name,
            address=str(class_sym.getAddress()),
            methods=self._find_methods_for_class(name, limit=100),
        )

        # Try to find superclass
        for sym in st.getAllSymbols(True):
            sym_name = sym.getName()
            if f"_OBJC_SUPERCLASS_$_{name}" in sym_name or f"{name}_superclass" in sym_name:
                # Would need to dereference to get actual superclass
                break

        self._class_cache[name] = cls
        return cls

    def decompile_method(self, signature: str, timeout: int = 30) -> dict:
        """Decompile an Objective-C method.

        Args:
            signature: Method signature like "-[NSObject init]" or just "init" with class context

        Returns:
            Dict with decompiled code and ObjC metadata
        """
        from pyghidra_lite.tools import GhidraTools
        tools = GhidraTools(self.handle)

        fm = self.program.getFunctionManager()
        target_func = None

        # Find the method
        for func in fm.getFunctions(True):
            name = func.getName()
            if name == signature or signature in name:
                target_func = func
                break

        if not target_func:
            raise ValueError(f"Method not found: {signature}")

        name = target_func.getName()
        result = tools.decompile_function(name, timeout=timeout)

        # Parse method info
        class_name = None
        selector = None
        is_class_method = False

        match = re.match(r'^([+-])\[(\w+)\s+(.+)\]$', name)
        if match:
            is_class_method = match.group(1) == "+"
            class_name = match.group(2)
            selector = match.group(3)

        return {
            "signature": name,
            "class": class_name,
            "selector": selector,
            "is_class_method": is_class_method,
            "address": str(target_func.getEntryPoint()),
            "code": result.code,
            "callees": result.callees,
            "strings": result.strings_used,
        }

    def find_method_calls(self, selector: str, limit: int = 50) -> list[dict]:
        """Find where a selector is called.

        Args:
            selector: The selector to search for (e.g., "initWithFrame:")
        """
        results = []
        fm = self.program.getFunctionManager()
        rm = self.program.getReferenceManager()

        # Find all methods with this selector
        target_methods = []
        for func in fm.getFunctions(True):
            name = func.getName()
            if selector in name:
                target_methods.append(func)

        # Find xrefs to these methods
        for method in target_methods:
            for ref in rm.getReferencesTo(method.getEntryPoint()):
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller:
                    results.append({
                        "caller": caller.getName(),
                        "caller_addr": str(ref.getFromAddress()),
                        "callee": method.getName(),
                        "callee_addr": str(method.getEntryPoint()),
                    })

                    if len(results) >= limit:
                        return results

        return results

    def search_strings_in_class(self, class_name: str) -> list[tuple[str, str]]:
        """Find strings used by methods of a class.

        Returns list of (method_signature, string_value)
        """
        from pyghidra_lite.tools import GhidraTools
        tools = GhidraTools(self.handle)

        results = []
        methods = self._find_methods_for_class(class_name, limit=100)

        for method in methods:
            try:
                decomp = tools.decompile_function(method.signature)
                for s in (decomp.strings_used or []):
                    results.append((method.signature, s))
            except Exception:
                pass

        return results

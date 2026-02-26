"""Swift and Objective-C language inspection tools for pyghidra-lite."""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)


# =============================================================================
# SWIFT
# =============================================================================

SWIFT_MANGLED_PREFIX = ("_$s", "$s", "_$S", "$S", "_T0", "_T")

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
    kind: str | None = None
    module: str | None = None
    type_name: str | None = None


@dataclass
class SwiftType:
    """Swift type information extracted from metadata."""
    name: str
    module: str | None = None
    kind: str | None = None  # struct, class, enum, protocol
    fields: list[tuple[str, str]] = field(default_factory=list)
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
    sections: dict[str, int] = field(default_factory=dict)


def is_swift_mangled(name: str) -> bool:
    """Check if a symbol name is Swift-mangled."""
    return any(name.startswith(prefix) for prefix in SWIFT_MANGLED_PREFIX)


def demangle_swift(mangled: str) -> str:
    """Demangle a Swift symbol name."""
    if not is_swift_mangled(mangled):
        return mangled

    # Try swift-demangle tool
    try:
        result = subprocess.run(
            ["swift-demangle", "-compact", mangled],
            capture_output=True, text=True, timeout=1,
        )
        if result.returncode == 0 and result.stdout.strip():
            demangled = result.stdout.strip()
            if demangled != mangled:
                return demangled
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        pass

    # Try xcrun swift-demangle (macOS)
    try:
        result = subprocess.run(
            ["xcrun", "swift-demangle", "-compact", mangled],
            capture_output=True, text=True, timeout=1,
        )
        if result.returncode == 0 and result.stdout.strip():
            demangled = result.stdout.strip()
            if demangled != mangled:
                return demangled
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        pass

    return _basic_demangle(mangled)


def _basic_demangle(mangled: str) -> str:
    """Basic Swift demangling without external tools."""
    name = mangled
    for prefix in SWIFT_MANGLED_PREFIX:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    parts = []
    i = 0
    while i < len(name):
        length_match = re.match(r'^(\d+)', name[i:])
        if length_match:
            length = int(length_match.group(1))
            i += len(length_match.group(1))
            if i + length <= len(name):
                parts.append(name[i:i + length])
                i += length
                continue
        i += 1

    if parts:
        return ".".join(parts)
    return mangled


def demangle_batch(names: list[str]) -> dict[str, str]:
    """Demangle multiple Swift names efficiently using batch mode."""
    swift_names = [n for n in names if is_swift_mangled(n)]
    if not swift_names:
        return {n: n for n in names}

    results = {n: n for n in names}

    try:
        input_text = "\n".join(swift_names)
        result = subprocess.run(
            ["swift-demangle", "-compact"],
            input=input_text, capture_output=True, text=True,
            timeout=max(5, len(swift_names) // 100),
        )
        if result.returncode == 0:
            demangled_lines = result.stdout.strip().split("\n")
            for mangled, demangled in zip(swift_names, demangled_lines, strict=False):
                if demangled and demangled != mangled:
                    results[mangled] = demangled
            return results
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        pass

    for name in swift_names:
        results[name] = _basic_demangle(name)
    return results


def extract_module_name(demangled: str) -> str | None:
    """Extract module name from demangled Swift symbol."""
    if "." in demangled:
        return demangled.split(".")[0]
    return None


def classify_swift_symbol(mangled: str, demangled: str) -> str:
    """Classify a Swift symbol by its type."""
    demangled_lower = demangled.lower()
    if "init" in demangled_lower and ("C" in mangled or ".init" in demangled):
        return "initializer"
    elif "getter" in demangled_lower:
        return "getter"
    elif "setter" in demangled_lower:
        return "setter"
    elif "subscript" in demangled_lower:
        return "subscript"
    elif ".deinit" in demangled:
        return "deinitializer"
    elif "witness" in demangled_lower:
        return "witness"
    elif "protocol" in demangled_lower:
        return "protocol"
    elif "metadata" in demangled_lower:
        return "metadata"
    elif "(" in demangled and ")" in demangled:
        return "function"
    elif demangled and demangled[0].isupper():
        return "type"
    return "unknown"


class SwiftTools:
    """Swift language inspection tools for a loaded binary."""

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program
        self._demangle_cache: dict[str, str] = {}

    def is_swift_binary(self) -> bool:
        """Check if the binary contains Swift code."""
        mem = self.program.getMemory()
        for block in mem.getBlocks():
            name = block.getName()
            if any(s in name for s in SWIFT_SECTIONS):
                return True

        st = self.program.getSymbolTable()
        count = 0
        for sym in st.getAllSymbols(True):
            if is_swift_mangled(sym.getName()):
                count += 1
                if count > 5:
                    return True
        return False

    def get_swift_info(self) -> SwiftInfo:
        """Get summary of Swift content in the binary."""
        mem = self.program.getMemory()
        st = self.program.getSymbolTable()

        sections = {}
        for block in mem.getBlocks():
            name = block.getName()
            for swift_section in SWIFT_SECTIONS:
                if swift_section in name:
                    sections[swift_section] = int(block.getSize())

        swift_names = []
        for sym in st.getAllSymbols(True):
            name = sym.getName()
            if is_swift_mangled(name):
                swift_names.append(name)

        demangled_map = demangle_batch(swift_names) if swift_names else {}
        self._demangle_cache.update(demangled_map)

        modules: dict[str, int] = {}
        for mangled in swift_names:
            demangled = demangled_map.get(mangled, mangled)
            module = extract_module_name(demangled)
            if module:
                modules[module] = modules.get(module, 0) + 1

        module_name = None
        if modules:
            user_modules = {
                m: c for m, c in modules.items()
                if m not in ("Swift", "Foundation", "Darwin", "ObjectiveC", "_")
            }
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
        self, pattern: str = "", limit: int = 50, kind: str | None = None,
    ) -> list[SwiftSymbol]:
        """List Swift functions with demangled names."""
        fm = self.program.getFunctionManager()

        swift_funcs = []
        for func in fm.getFunctions(True):
            name = func.getName()
            if is_swift_mangled(name):
                swift_funcs.append((func, name))

        mangled_names = [n for _, n in swift_funcs]
        demangled_map = demangle_batch(mangled_names)

        results = []
        for func, mangled in swift_funcs:
            demangled_name = demangled_map.get(mangled, mangled)

            if pattern and pattern.lower() not in demangled_name.lower():
                continue

            sym_kind = classify_swift_symbol(mangled, demangled_name)
            if kind and sym_kind != kind:
                continue

            results.append(SwiftSymbol(
                mangled=mangled,
                demangled=demangled_name,
                address=str(func.getEntryPoint()),
                kind=sym_kind,
                module=extract_module_name(demangled_name),
            ))

            if len(results) >= limit:
                break

        return results

    def list_swift_types(self, limit: int = 50) -> list[SwiftType]:
        """Extract Swift types from metadata sections."""
        st = self.program.getSymbolTable()
        types = {}

        for sym in st.getAllSymbols(True):
            name = sym.getName()
            if not is_swift_mangled(name):
                continue

            demangled = self.demangle(name)

            if "type metadata accessor" in demangled.lower():
                match = re.search(r"type metadata accessor for (.+)", demangled)
                if match:
                    type_name = match.group(1)
                    if type_name not in types:
                        types[type_name] = SwiftType(
                            name=type_name.split(".")[-1] if "." in type_name else type_name,
                            module=extract_module_name(type_name),
                            address=str(sym.getAddress()),
                        )
            elif "nominal type descriptor" in demangled.lower():
                match = re.search(r"nominal type descriptor for (.+)", demangled)
                if match:
                    type_name = match.group(1)
                    if type_name not in types:
                        kind = None
                        dl = demangled.lower()
                        if "struct" in dl:
                            kind = "struct"
                        elif "class" in dl:
                            kind = "class"
                        elif "enum" in dl:
                            kind = "enum"
                        types[type_name] = SwiftType(
                            name=type_name.split(".")[-1] if "." in type_name else type_name,
                            module=extract_module_name(type_name),
                            kind=kind,
                            address=str(sym.getAddress()),
                        )

            if len(types) >= limit:
                break

        return list(types.values())[:limit]


# =============================================================================
# OBJECTIVE-C
# =============================================================================

# Common ObjC frameworks
OBJC_FRAMEWORKS = {
    "NSObject": "Foundation",
    "NSString": "Foundation",
    "NSArray": "Foundation",
    "NSDictionary": "Foundation",
    "NSData": "Foundation",
    "NSURL": "Foundation",
    "NSError": "Foundation",
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
    methods: list["ObjCMethod"] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
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
        prefix = "+" if self.is_class_method else "-"
        if self.class_name:
            return f"{prefix}[{self.class_name} {self.selector}]"
        return f"{prefix}{self.selector}"


@dataclass
class ObjCInfo:
    """Summary of Objective-C content in a binary."""
    has_objc: bool
    num_classes: int = 0
    num_categories: int = 0
    num_protocols: int = 0
    num_selectors: int = 0
    has_arc: bool = False
    frameworks: list[str] = field(default_factory=list)


def is_objc_symbol(name: str) -> bool:
    """Check if a symbol is Objective-C related."""
    objc_patterns = [
        r'^[+-]\[',
        r'^_OBJC_',
        r'^_objc_',
    ]
    return any(re.match(p, name) for p in objc_patterns)


class ObjCTools:
    """Objective-C inspection tools."""

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program
        self._class_cache: dict[str, ObjCClass] = {}

    def has_objc(self) -> bool:
        """Check if binary contains Objective-C code."""
        mem = self.program.getMemory()
        for block in mem.getBlocks():
            name = block.getName()
            if any(s in name for s in ["__objc_", "objc_class", "objc_data"]):
                return True

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
            elif "_$_category_" in name.lower():
                categories.add(name)
            elif name.startswith("_OBJC_PROTOCOL_$_"):
                protocols.add(name.replace("_OBJC_PROTOCOL_$_", ""))
            elif re.match(r'^[+-]\[', name):
                match = re.match(r'^[+-]\[\w+\s+(.+)\]$', name)
                if match:
                    selectors.add(match.group(1))

        has_arc = False
        fm = self.program.getFunctionManager()
        for func in fm.getFunctions(True):
            fname = func.getName()
            if any(s in fname for s in ("objc_retain", "objc_release", "objc_autoreleaseReturnValue")):
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
        """List Objective-C classes."""
        st = self.program.getSymbolTable()
        classes = {}

        for sym in st.getAllSymbols(True):
            name = sym.getName()
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

        for class_name, cls in classes.items():
            cls.methods = self._find_methods_for_class(class_name, limit=20)

        return list(classes.values())[:limit]

    def _find_methods_for_class(self, class_name: str, limit: int = 50) -> list[ObjCMethod]:
        """Find methods belonging to a class."""
        fm = self.program.getFunctionManager()
        methods = []
        pattern = re.compile(rf'^([+-])\[{re.escape(class_name)}\s+(.+)\]$')

        for func in fm.getFunctions(True):
            match = pattern.match(func.getName())
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
        self, pattern: str = "", class_name: str | None = None, limit: int = 50,
    ) -> list[ObjCMethod]:
        """List Objective-C methods."""
        fm = self.program.getFunctionManager()
        methods = []
        method_pattern = re.compile(r'^([+-])\[(\w+)\s+(.+)\]$')

        for func in fm.getFunctions(True):
            match = method_pattern.match(func.getName())
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

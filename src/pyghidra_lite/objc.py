"""Objective-C specific analysis tools for pyghidra-lite."""

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)

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

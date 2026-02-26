"""High-level analyzer API for pyghidra-lite."""

from pathlib import Path
from typing import TYPE_CHECKING

from pyghidra_lite.backend import GhidraBackend, ProgramHandle
from pyghidra_lite.formats import MachODylib, MachOInfo, MachOSection, MachOSegment, MachOTools
from pyghidra_lite.lang import (
    ObjCClass,
    ObjCInfo,
    ObjCMethod,
    ObjCProtocol,
    ObjCTools,
    SwiftInfo,
    SwiftSymbol,
    SwiftTools,
    SwiftType,
)
from pyghidra_lite.models import AnalysisProfile
from pyghidra_lite.tools import GhidraTools

if TYPE_CHECKING:
    from pyghidra_lite.models import (
        BytesResult,
        CrossRef,
        DecompiledFunction,
        ExportInfo,
        FunctionInfo,
        ImportInfo,
        StringXref,
        SymbolInfo,
    )


class GhidraAnalyzer:
    """High-level API for binary analysis with Ghidra.

    Example:
        analyzer = GhidraAnalyzer()
        analyzer.load("/path/to/binary", profile="fast")

        # List functions
        for func in analyzer.functions(limit=20):
            print(func.name, func.address)

        # Decompile
        code = analyzer.decompile("main")
        print(code.code)
    """

    def __init__(
        self,
        project_name: str = "pyghidra_lite",
        project_dir: Path | str | None = None,
    ):
        """Initialize analyzer.

        Args:
            project_name: Ghidra project name (use different names for concurrent access)
            project_dir: Project directory (default: ~/.local/share/pyghidra-lite/projects)
        """
        if isinstance(project_dir, str):
            project_dir = Path(project_dir)
        self._backend = GhidraBackend(
            project_name=project_name,
            project_dir=project_dir,
        )
        self._current: ProgramHandle | None = None
        self._tools: GhidraTools | None = None
        self._swift: SwiftTools | None = None
        self._macho: MachOTools | None = None
        self._objc: ObjCTools | None = None

    def load(
        self,
        path: Path | str,
        profile: AnalysisProfile | str = "default",
        analyze: bool = True,
    ) -> "GhidraAnalyzer":
        """Load and analyze a binary.

        Args:
            path: Path to binary file
            profile: Analysis depth - "fast", "default", or "deep"
            analyze: Run analysis (set False for large binaries to avoid timeout)

        Returns:
            self for chaining
        """
        handle = self._backend.import_binary(path, profile=profile, analyze=analyze)
        self._current = handle
        self._tools = GhidraTools(handle)
        self._swift = SwiftTools(handle)
        self._macho = MachOTools(handle)
        self._objc = ObjCTools(handle)
        return self

    def select(self, name: str) -> "GhidraAnalyzer":
        """Select an already-loaded binary by name.

        Args:
            name: Binary name or partial match

        Returns:
            self for chaining
        """
        handle = self._backend.get_program(name)
        self._current = handle
        self._tools = GhidraTools(handle)
        self._swift = SwiftTools(handle)
        self._macho = MachOTools(handle)
        self._objc = ObjCTools(handle)
        return self

    def reanalyze(self, profile: AnalysisProfile | str = "deep") -> "GhidraAnalyzer":
        """Re-run analysis with a different profile.

        Args:
            profile: New analysis profile

        Returns:
            self for chaining
        """
        if not self._current:
            raise RuntimeError("No binary loaded. Call load() first.")
        self._backend.analyze_program(self._current.name, profile)
        return self

    @property
    def programs(self) -> list[str]:
        """List all loaded programs."""
        return self._backend.list_programs()

    @property
    def current(self) -> ProgramHandle | None:
        """Current program handle."""
        return self._current

    @property
    def info(self) -> dict:
        """Get current binary metadata."""
        if not self._current:
            raise RuntimeError("No binary loaded. Call load() first.")
        return {
            "name": self._current.name,
            "unit_id": self._current.unit_id,
            "profile": self._current.profile.value,
            "analyzed": self._current.analyzed,
            "metadata": self._current.metadata,
        }

    def _require_tools(self) -> GhidraTools:
        if not self._tools:
            raise RuntimeError("No binary loaded. Call load() first.")
        return self._tools

    def _require_swift(self) -> SwiftTools:
        if not self._swift:
            raise RuntimeError("No binary loaded. Call load() first.")
        return self._swift

    def _require_macho(self) -> MachOTools:
        if not self._macho:
            raise RuntimeError("No binary loaded. Call load() first.")
        return self._macho

    def _require_objc(self) -> ObjCTools:
        if not self._objc:
            raise RuntimeError("No binary loaded. Call load() first.")
        return self._objc

    # === Analysis methods ===

    def functions(
        self,
        pattern: str = "",
        limit: int = 50,
        sort_by: str = "name",
    ) -> list["FunctionInfo"]:
        """List functions.

        Args:
            pattern: Filter by name substring
            limit: Max results
            sort_by: "name", "refs_in" (importance), "refs_out" (complexity), "size"
        """
        return self._require_tools().list_functions(
            pattern=pattern, limit=limit, sort_by=sort_by
        )

    def decompile(self, function: str, timeout: int = 30) -> "DecompiledFunction":
        """Decompile a function.

        Args:
            function: Function name or address (0x...)
            timeout: Decompilation timeout in seconds
        """
        return self._require_tools().decompile_function(function, timeout=timeout)

    def imports(self, pattern: str = "", limit: int = 50) -> list["ImportInfo"]:
        """List imports with capability tags."""
        return self._require_tools().list_imports(pattern=pattern, limit=limit)

    def exports(self, pattern: str = "", limit: int = 50) -> list["ExportInfo"]:
        """List exports."""
        return self._require_tools().list_exports(pattern=pattern, limit=limit)

    def xrefs_to(self, target: str, limit: int = 50) -> list["CrossRef"]:
        """Get cross-references TO a target (who calls/uses this)."""
        return self._require_tools().get_xrefs(target, limit=limit)

    def callees(self, function: str) -> list[str]:
        """Get functions called BY this function."""
        return self._require_tools().get_callees(function)

    def strings(self, query: str = "", limit: int = 30) -> list["StringXref"]:
        """Search strings with cross-references."""
        return self._require_tools().search_strings(query, limit=limit)

    def symbols(self, query: str, limit: int = 30) -> list["SymbolInfo"]:
        """Search symbols by name."""
        return self._require_tools().search_symbols(query, limit=limit)

    def read_bytes(self, address: str, size: int) -> "BytesResult":
        """Read raw bytes at address."""
        return self._require_tools().read_bytes(address, size)

    def read_string(self, address: str) -> str:
        """Read null-terminated string at address."""
        return self._require_tools().read_string(address)

    def delete(self, name: str | None = None) -> bool:
        """Delete a binary from the project.

        Args:
            name: Binary name (defaults to current)
        """
        if name is None:
            if not self._current:
                raise RuntimeError("No binary loaded.")
            name = self._current.name
            self._current = None
            self._tools = None
            self._swift = None
        return self._backend.delete_program(name)

    # === Swift methods ===

    def is_swift(self) -> bool:
        """Check if the binary contains Swift code."""
        return self._require_swift().is_swift_binary()

    def swift_info(self) -> SwiftInfo:
        """Get summary of Swift content in the binary."""
        return self._require_swift().get_swift_info()

    def swift_functions(
        self,
        pattern: str = "",
        limit: int = 50,
        kind: str | None = None,
    ) -> list[SwiftSymbol]:
        """List Swift functions with demangled names.

        Args:
            pattern: Filter by demangled name substring
            limit: Max results
            kind: Filter by kind (function, initializer, getter, setter, witness, etc.)
        """
        return self._require_swift().list_swift_functions(
            pattern=pattern, limit=limit, kind=kind
        )

    def swift_types(self, limit: int = 50) -> list[SwiftType]:
        """Extract Swift types from metadata."""
        return self._require_swift().list_swift_types(limit=limit)

    def swift_decompile(self, function: str, timeout: int = 30) -> dict:
        """Decompile a Swift function with enhanced metadata.

        Args:
            function: Function name (mangled or demangled) or address

        Returns:
            Dict with code, demangled name, callees, etc.
        """
        return self._require_swift().decompile_swift(function, timeout=timeout)

    def demangle(self, name: str) -> str:
        """Demangle a Swift symbol name."""
        return self._require_swift().demangle(name)

    # === Mach-O methods ===

    def is_macho(self) -> bool:
        """Check if binary is Mach-O format."""
        return self._require_macho().is_macho()

    def macho_info(self) -> MachOInfo:
        """Get Mach-O binary structure summary."""
        return self._require_macho().get_macho_info()

    def segments(self) -> list[MachOSegment]:
        """List Mach-O segments."""
        return self._require_macho().list_segments()

    def sections(self) -> list[MachOSection]:
        """List Mach-O sections."""
        return self._require_macho().list_sections()

    def dylibs(self) -> list[MachODylib]:
        """List linked dynamic libraries."""
        return self._require_macho().list_dylibs()

    def read_section(self, name: str) -> bytes | None:
        """Read raw bytes from a Mach-O section."""
        return self._require_macho().read_section(name)

    # === Objective-C methods ===

    def has_objc(self) -> bool:
        """Check if binary contains Objective-C code."""
        return self._require_objc().has_objc()

    def objc_info(self) -> ObjCInfo:
        """Get summary of Objective-C content."""
        return self._require_objc().get_objc_info()

    def objc_classes(self, pattern: str = "", limit: int = 50) -> list[ObjCClass]:
        """List Objective-C classes.

        Args:
            pattern: Filter by class name substring
            limit: Max results
        """
        return self._require_objc().list_classes(pattern=pattern, limit=limit)

    def objc_methods(
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
        return self._require_objc().list_methods(
            pattern=pattern, class_name=class_name, limit=limit
        )

    def objc_selectors(self, pattern: str = "", limit: int = 50) -> list[str]:
        """List unique Objective-C selectors."""
        return self._require_objc().list_selectors(pattern=pattern, limit=limit)

    def objc_protocols(self, limit: int = 50) -> list[ObjCProtocol]:
        """List Objective-C protocols."""
        return self._require_objc().list_protocols(limit=limit)

    def objc_class(self, name: str) -> ObjCClass | None:
        """Get detailed information about an Objective-C class."""
        return self._require_objc().get_class(name)

    def objc_decompile(self, signature: str, timeout: int = 30) -> dict:
        """Decompile an Objective-C method.

        Args:
            signature: Method signature like "-[NSObject init]"
        """
        return self._require_objc().decompile_method(signature, timeout=timeout)

    # === Combined Apple platform methods ===

    def apple_summary(self) -> dict:
        """Get summary of Apple platform binary (Mach-O + Swift + ObjC)."""
        macho = self.macho_info() if self.is_macho() else None
        swift = self.swift_info() if macho else None
        objc = self.objc_info() if macho else None

        return {
            "is_macho": macho.is_macho if macho else False,
            "cpu_type": macho.cpu_type if macho else None,
            "has_swift": swift.is_swift if swift else False,
            "swift_module": swift.module_name if swift else None,
            "has_objc": objc.has_objc if objc else False,
            "objc_classes": objc.num_classes if objc else 0,
            "frameworks": objc.frameworks if objc else [],
            "dylibs": [d.name for d in self.dylibs()] if macho else [],
        }

    def close(self) -> None:
        """Close the analyzer and release resources."""
        self._backend.close()
        self._current = None
        self._tools = None
        self._swift = None
        self._macho = None
        self._objc = None

    def __enter__(self) -> "GhidraAnalyzer":
        return self

    def __exit__(self, *args) -> None:
        self.close()

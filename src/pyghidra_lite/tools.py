"""Ghidra tool implementations for pyghidra-lite."""

import logging
import re
import time
from typing import TYPE_CHECKING

from pyghidra_lite.backend import ProgramHandle, compute_stable_id
from pyghidra_lite.models import (
    BytesResult,
    CrossRef,
    DecompiledFunction,
    EmbeddedRuntime,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    StringXref,
    SymbolInfo,
)

if TYPE_CHECKING:
    from ghidra.program.model.listing import Function

    from pyghidra_lite.backend import GhidraBackend

logger = logging.getLogger(__name__)

# Cache TTL in seconds (functions don't change during analysis session)
CACHE_TTL = 300

# Upper bounds for call-graph traversal so a high-fan-out function at depth=5
# can't emit thousands of nodes/edges in a single response.
MAX_GRAPH_NODES = 250
MAX_GRAPH_EDGES = 1000

# Capability tags for common APIs
CAPABILITY_TAGS = {
    # Crypto
    "crypto": ["aes", "des", "rsa", "sha", "md5", "encrypt", "decrypt", "cipher", "hash", "hmac",
               "ssl", "tls", "crypto", "pkcs", "x509", "certificate", "digest"],
    # Network
    "network": ["socket", "connect", "send", "recv", "http", "url", "dns", "inet", "tcp", "udp",
                "curl", "fetch", "request", "download", "upload", "websocket"],
    # File
    "file": ["open", "read", "write", "close", "file", "fopen", "fread", "fwrite", "fclose",
             "path", "directory", "mkdir", "remove", "unlink", "stat"],
    # Process
    "process": ["exec", "spawn", "fork", "system", "popen", "process", "thread", "pthread",
                "kill", "signal", "wait", "exit"],
    # Memory
    "memory": ["malloc", "free", "alloc", "realloc", "mmap", "memcpy", "memset", "heap", "stack"],
    # JNI (Android)
    "jni": ["jni", "java", "dalvik", "findclass", "getmethod", "callmethod", "getfield"],
}


# Runtime payload signatures for detect_embedded_runtime()
# Each entry: type, magic (hex), base confidence, strategy, and optional adjustments.
_RUNTIME_SIGNATURES: list[dict] = [
    {"type": "bunfs",          "magic": "42554e00",               "confidence": "high",   "strategy": "external_tools"},
    {"type": "electron_asar",  "magic": "41534152",               "confidence": "high",   "strategy": "search_payload",  "section_adjust": True},
    {"type": "node_sea",       "magic": "4e4f44455f5345415f46555345", "confidence": "high", "strategy": "search_payload", "strtab_fp": True},
    {"type": "pyinstaller",    "magic": "4d45490e34120100",        "confidence": "high",   "strategy": "external_tools"},
    {"type": "upx",            "magic": "55505821",                "confidence": "high",   "strategy": "unpack_first"},
    {"type": "v8_snapshot",    "magic": "d80dcace",                "confidence": "medium", "strategy": "external_tools",  "symbol": "v8_snapshot_blob_data"},
    {"type": "lua_bytecode",   "magic": "1b4c7561",                "confidence": "high",   "strategy": "external_tools"},
]


_NAME_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
# Keywords of 4+ chars match a token prefix (recv -> recvfrom); these would
# then over-match (stat -> status, exit -> exiting) so they need the whole token.
_EXACT_KEYWORDS = {"stat", "free", "exit", "wait", "kill", "path"}
# Windows thread-local-storage APIs (TlsAlloc, TlsGetValue, ...) are not TLS crypto.
_WIN_TLS_STORAGE = {"alloc", "free", "get", "set"}


def get_capability_tags(name: str) -> list[str]:
    """Get capability tags for an import/export name.

    Matches keywords against name tokens (split on case changes, "_" and
    digits) rather than raw substrings, which tagged GetCPInfo as network
    ("tcp" in "getcpinfo"), CreateThread as file ("read") and
    destroy_window as crypto ("des").
    """
    tokens = [t.lower() for t in _NAME_TOKEN.findall(name)]
    if not tokens:
        return []
    runs = re.findall(r"[a-z0-9]+", name.lower())  # keeps "x509", "md5" whole
    win_tls = tokens[0] == "tls" and len(tokens) > 1 and tokens[1] in _WIN_TLS_STORAGE

    def hit(kw: str) -> bool:
        if kw == "tls" and win_tls:
            return False
        if any(c.isdigit() for c in kw):
            return any(r.startswith(kw) for r in runs)
        if len(kw) <= 3 or kw in _EXACT_KEYWORDS:
            return kw in tokens
        return any(t.startswith(kw) for t in tokens)

    return [tag for tag, keywords in CAPABILITY_TAGS.items() if any(hit(kw) for kw in keywords)]


class GhidraTools:
    """Tool implementations using Ghidra APIs.

    Includes caching for expensive operations to improve performance
    on repeated queries within the same session.
    """

    def __init__(self, handle: ProgramHandle):
        if not isinstance(handle, ProgramHandle):
            raise TypeError(
                f"GhidraTools requires a ProgramHandle, got {type(handle).__name__}. "
                f"Use GhidraTools.from_backend(backend, binary_name) instead."
            )
        self.handle = handle
        self.program = handle.program
        self.decompiler = handle.decompiler

        # Caches with timestamps
        self._functions_cache: list[FunctionInfo] | None = None
        self._functions_cache_time: float = 0
        self._function_name_index: dict[str, Function] | None = None
        self._symbols_cache: dict[str, list[SymbolInfo]] | None = None

    def invalidate_cache(self) -> None:
        """Invalidate all caches (call after re-analysis)."""
        self._functions_cache = None
        self._functions_cache_time = 0
        self._function_name_index = None
        self._symbols_cache = None

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid."""
        return (self._functions_cache is not None and
                time.time() - self._functions_cache_time < CACHE_TTL)

    def _build_function_index(self) -> dict[str, "Function"]:
        """Build name-to-function index for fast lookup."""
        if self._function_name_index is not None:
            return self._function_name_index

        fm = self.program.getFunctionManager()
        index: dict[str, Function] = {}

        for func in fm.getFunctions(True):
            name = func.getName()
            index[name] = func
            # Also index lowercase for case-insensitive lookup
            index[name.lower()] = func

        self._function_name_index = index
        return index

    @classmethod
    def from_backend(cls, backend: "GhidraBackend", binary: str) -> "GhidraTools":
        """Create GhidraTools from a backend and binary name.

        Args:
            backend: GhidraBackend instance
            binary: Binary name or unit_id
        """
        from pyghidra_lite.backend import GhidraBackend
        if not isinstance(backend, GhidraBackend):
            raise TypeError(f"Expected GhidraBackend, got {type(backend).__name__}")
        handle = backend.get_program(binary)
        return cls(handle)

    def list_functions(
        self,
        pattern: str = "",
        limit: int = 50,
        sort_by: str = "name",
        include_thunks: bool = False,
        include_external: bool = False,
        include_metadata: bool = True,
    ) -> list[FunctionInfo]:
        """List functions with optional metadata annotations.

        Args:
            pattern: Filter by name substring (case-insensitive).
            limit: Max results (default 50).
            sort_by: Sort order - "name", "refs_in", "refs_out", or "size".
            include_thunks: Include thunk/trampoline functions.
            include_external: Include external functions.
            include_metadata: Include refs_in/refs_out counts (slower if True).

        Returns:
            List of FunctionInfo objects.
        """
        # Use cached results if available and no filtering
        if (self._is_cache_valid() and not pattern and
            not include_thunks and not include_external and include_metadata):
            results = self._functions_cache[:]
        else:
            results = self._build_function_list(
                include_thunks, include_external, include_metadata
            )
            # Cache unfiltered results
            if not pattern and not include_thunks and not include_external:
                self._functions_cache = results[:]
                self._functions_cache_time = time.time()

        # Filter by pattern
        if pattern:
            pattern_lower = pattern.lower()
            results = [f for f in results if pattern_lower in f.name.lower()]

        # Sort
        if sort_by == "refs_in":
            results.sort(key=lambda f: f.refs_in or 0, reverse=True)
        elif sort_by == "refs_out":
            results.sort(key=lambda f: f.refs_out or 0, reverse=True)
        elif sort_by == "size":
            results.sort(key=lambda f: f.size or 0, reverse=True)
        else:
            results.sort(key=lambda f: f.name)

        return results[:limit]

    def _build_function_list(
        self,
        include_thunks: bool,
        include_external: bool,
        include_metadata: bool,
    ) -> list[FunctionInfo]:
        """Build function list (internal, may be cached)."""
        fm = self.program.getFunctionManager()
        rm = self.program.getReferenceManager() if include_metadata else None

        results = []
        for func in fm.getFunctions(True):
            func: Function
            if not include_external and func.isExternal():
                continue
            if not include_thunks and func.isThunk():
                continue

            entry = func.getEntryPoint()

            # Only compute refs if metadata requested (expensive)
            refs_in = None
            refs_out = None
            if include_metadata and rm:
                try:
                    refs_in = len(list(rm.getReferencesTo(entry)))
                    refs_out = len(list(func.getCalledFunctions(None)))
                except Exception as e:
                    logger.debug("Failed to get refs for %s: %s", func.getName(), e)

            # Note: has_strings is deferred to get_function_info for performance
            # Checking every address in every function is O(n*m) - too expensive

            results.append(FunctionInfo(
                name=func.getName(),
                address=str(entry),
                stable_id=compute_stable_id(self.handle.unit_id, str(entry)),
                size=int(func.getBody().getNumAddresses()),
                refs_in=refs_in,
                refs_out=refs_out,
                has_strings=None,  # Deferred to get_function_info
                is_library=func.getName().startswith("FID_"),
                is_thunk=func.isThunk(),
            ))

        return results

    def decompile_function(
        self,
        name_or_addr: str,
        timeout: int = 30,
        include_callees: bool = True,
        include_strings: bool = True,
        include_provenance: bool = False,
        include_refs: bool = True,
    ) -> DecompiledFunction:
        """Decompile a function.

        Args:
            name_or_addr: Function name or hex address (0x...).
            timeout: Decompilation timeout in seconds (default 30).
            include_callees: Include list of called functions (default True).
            include_strings: Include referenced strings (default True).
            include_provenance: Include analysis provenance (default False, saves tokens).
            include_refs: Include refs_in/refs_out counts (default True).

        Returns:
            DecompiledFunction with code and optional metadata.
        """
        from ghidra.util.task import ConsoleTaskMonitor

        func = self._find_function(name_or_addr)
        if not func:
            raise ValueError(f"Function not found: {name_or_addr}")

        monitor = ConsoleTaskMonitor()
        result = self.decompiler.decompileFunction(func, timeout, monitor)

        if result.getErrorMessage():
            code = f"// Decompilation error: {result.getErrorMessage()}"
            signature = None
        else:
            # Ghidra emits CRLF on Windows plus blank padding lines; both
            # cost tokens and carry nothing.
            code = str(result.decompiledFunction.getC()).replace("\r\n", "\n").strip("\n")
            signature = result.decompiledFunction.getSignature()

        entry = func.getEntryPoint()

        # Only compute expensive fields if requested
        callees = None
        strings_used = None
        refs_in = None
        refs_out = None

        if include_callees:
            callees = [f.getName() for f in func.getCalledFunctions(None)]
            if not callees:
                callees = None

        if include_strings:
            strings_used = self._get_function_strings(func)
            if not strings_used:
                strings_used = None

        if include_refs:
            rm = self.program.getReferenceManager()
            refs_in = len(list(rm.getReferencesTo(entry)))
            refs_out = len(callees) if callees else len(list(func.getCalledFunctions(None)))

        return DecompiledFunction(
            name=func.getName(),
            address=str(entry),
            stable_id=compute_stable_id(self.handle.unit_id, str(entry)),
            signature=signature,
            code=code,
            refs_in=refs_in,
            refs_out=refs_out,
            callees=callees,
            strings_used=strings_used,
            provenance=self.handle.get_provenance() if include_provenance else None,
        )

    def get_cfg(self, name_or_addr: str) -> list[dict]:
        """Extract control flow graph (basic blocks + edges) for a function.

        Returns a list of basic blocks with their addresses, sizes, and
        successor edges. Useful for structural analysis without running
        the expensive Decompiler Parameter ID pass.
        """
        from ghidra.program.model.block import BasicBlockModel
        from ghidra.util.task import ConsoleTaskMonitor

        func = self._find_function(name_or_addr)
        if not func:
            raise ValueError(f"Function not found: {name_or_addr}")

        monitor = ConsoleTaskMonitor()
        bbm = BasicBlockModel(self.program)
        blocks = []
        block_iter = bbm.getCodeBlocksContaining(func.getBody(), monitor)
        while block_iter.hasNext():
            block = block_iter.next()
            successors = []
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext():
                dest = dest_iter.next()
                # Use full address string to preserve address space qualifier
                # (avoids collisions on binaries with EXTERNAL/overlay spaces)
                successors.append(str(dest.getDestinationAddress()))
            blocks.append({
                "addr": str(block.getFirstStartAddress()),
                "size": int(block.getNumAddresses()),
                "successors": successors,
            })
        return blocks

    def _find_function(self, name_or_addr: str) -> "Function | None":
        """Find a function by name or address.

        Uses indexed lookup for O(1) name resolution instead of O(n) iteration.
        Falls back to substring matching if exact match fails.
        """
        fm = self.program.getFunctionManager()

        # Try as address first (fast path)
        if name_or_addr.startswith("0x") or name_or_addr.startswith("0X"):
            try:
                addr = self.program.getAddressFactory().getAddress(
                    name_or_addr[2:] if name_or_addr.startswith(("0x", "0X")) else name_or_addr
                )
                func = fm.getFunctionAt(addr)
                if func:
                    return func
            except Exception as e:
                logger.debug("Address lookup failed for %s: %s", name_or_addr, e)

        # Build/use function index for O(1) lookup
        index = self._build_function_index()

        # Exact match (case-sensitive)
        if name_or_addr in index:
            return index[name_or_addr]

        # Case-insensitive match
        lower_name = name_or_addr.lower()
        if lower_name in index:
            return index[lower_name]

        # Substring match as last resort (single pass)
        for func in fm.getFunctions(True):
            if name_or_addr.lower() in func.getName().lower():
                return func

        return None

    def _get_function_strings(self, func: "Function", max_strings: int = 20) -> list[str]:
        """Get string literals referenced by a function.

        Args:
            func: The function to analyze.
            max_strings: Maximum strings to return (default 20).

        Returns:
            List of unique string values found.
        """
        strings = []
        rm = self.program.getReferenceManager()
        listing = self.program.getListing()
        seen = set()

        try:
            body = func.getBody()
            for addr in body.getAddresses(True):
                refs = rm.getReferencesFrom(addr)
                for ref in refs:
                    try:
                        data = listing.getDataAt(ref.getToAddress())
                        if data and data.hasStringValue():
                            val = str(data.getValue())
                            if val and len(val) > 1 and val not in seen:
                                seen.add(val)
                                strings.append(val)
                                if len(strings) >= max_strings:
                                    return strings
                    except Exception as e:
                        logger.debug("String extraction failed at %s: %s", addr, e)
        except Exception as e:
            logger.debug("String scan failed for %s: %s", func.getName(), e)

        return strings

    def get_xrefs(self, target: str, limit: int = 50) -> list[CrossRef]:
        """Get cross-references to a target."""
        addr = self._resolve_address(target)
        if not addr:
            raise ValueError(f"Could not resolve: {target}")

        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        results = []

        for ref in rm.getReferencesTo(addr):
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            results.append(CrossRef(
                from_addr=str(ref.getFromAddress()),
                to_addr=str(ref.getToAddress()),
                type=str(ref.getReferenceType()),
                from_func=from_func.getName() if from_func else None,
            ))
            if len(results) >= limit:
                break

        return results

    def get_callees(self, function: str) -> list[str]:
        """Get functions called by a function."""
        func = self._find_function(function)
        if not func:
            raise ValueError(f"Function not found: {function}")
        return [f.getName() for f in func.getCalledFunctions(None)]

    def _resolve_address(self, name_or_addr: str):
        """Resolve a name or address string to an Address.

        "0x..." is always an address. Anything else is looked up as a symbol
        first: names like "add", "dead" or "face" are valid hex, and parsing
        them as addresses first silently pointed at 0xadd etc. Bare hex is
        only taken as an address when no symbol has that name.
        """
        af = self.program.getAddressFactory()

        def as_address(text: str):
            try:
                return af.getAddress(text)
            except Exception:
                return None

        if name_or_addr[:2] in ("0x", "0X"):
            return as_address(name_or_addr[2:])

        st = self.program.getSymbolTable()
        for sym in st.getSymbols(name_or_addr):
            return sym.getAddress()
        lower = name_or_addr.lower()
        for sym in st.getAllSymbols(True):
            if sym.getName().lower() == lower:
                return sym.getAddress()

        return as_address(name_or_addr)

    def list_imports(self, pattern: str = "", limit: int = 50) -> list[ImportInfo]:
        """List imports with capability tags."""
        st = self.program.getSymbolTable()
        results = []

        for sym in st.getExternalSymbols():
            name = sym.getName()
            if pattern and pattern.lower() not in name.lower():
                continue

            tags = get_capability_tags(name)
            lib = str(sym.getParentNamespace())

            results.append(ImportInfo(
                name=name,
                library=lib,
                tags=tags if tags else None,
            ))

            if len(results) >= limit:
                break

        return results

    def list_exports(self, pattern: str = "", limit: int = 50) -> list[ExportInfo]:
        """List exported symbols."""
        st = self.program.getSymbolTable()
        results = []

        for sym in st.getAllSymbols(True):
            if not sym.isExternalEntryPoint():
                continue
            name = sym.getName()
            if pattern and pattern.lower() not in name.lower():
                continue

            results.append(ExportInfo(
                name=name,
                address=str(sym.getAddress()),
            ))

            if len(results) >= limit:
                break

        return results

    def search_strings(self, query: str, limit: int = 30) -> list[StringXref]:
        """Search strings with xrefs."""
        try:
            from ghidra.program.util import DefinedStringIterator
            data_iter = DefinedStringIterator.forProgram(self.program)
        except (ImportError, AttributeError):
            from ghidra.program.util import DefinedDataIterator
            data_iter = DefinedDataIterator.definedStrings(self.program)

        mem = self.program.getMemory()
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        results = []
        query_lower = query.lower()

        for data in data_iter:
            try:
                val = str(data.getValue())
                if query_lower not in val.lower():
                    continue

                # Get referencing functions
                refs = []
                for ref in rm.getReferencesTo(data.getAddress()):
                    func = fm.getFunctionContaining(ref.getFromAddress())
                    if func:
                        refs.append(func.getName())
                refs = list(set(refs))[:5]

                # Detect type
                looks_like = None
                if val.startswith(("http://", "https://", "ftp://")):
                    looks_like = "url"
                elif "/" in val and not val.startswith("//"):
                    looks_like = "path"
                elif "%" in val:
                    looks_like = "format_string"
                elif any(kw in val.lower() for kw in ["error", "fail", "invalid"]):
                    looks_like = "error"
                elif any(kw in val.lower() for kw in ["key", "token", "secret", "password"]):
                    looks_like = "key"

                # Get section name
                block = mem.getBlock(data.getAddress())
                section = block.getName() if block else None

                # Truncate very long strings to save tokens
                truncated_val = val[:500] if len(val) > 500 else val
                results.append(StringXref(
                    value=truncated_val,
                    address=str(data.getAddress()),
                    refs=refs,
                    looks_like=looks_like,
                    section=section,
                ))

                if len(results) >= limit:
                    break
            except Exception:
                continue

        return results

    def search_symbols(self, query: str, limit: int = 30) -> list[SymbolInfo]:
        """Search symbols by name."""
        st = self.program.getSymbolTable()
        results = []
        query_lower = query.lower()

        for sym in st.getAllSymbols(True):
            if query_lower not in sym.getName().lower():
                continue

            sym_type = str(sym.getSymbolType())
            is_lib = sym.getName().startswith("FID_")

            results.append(SymbolInfo(
                name=sym.getName(),
                address=str(sym.getAddress()),
                type=sym_type.lower(),
                is_library=is_lib,
            ))

            if len(results) >= limit:
                break

        return results

    def read_bytes(
        self,
        address: str,
        size: int,
        include_provenance: bool = False,
    ) -> BytesResult:
        """Read raw bytes at an address.

        Args:
            address: Hex address (0x...) or symbol name.
            size: Number of bytes to read (1-4096).
            include_provenance: Include analysis provenance (default False).

        Returns:
            BytesResult with hex and ASCII representation.

        Raises:
            ValueError: If size is out of range or address is invalid.
        """
        from jpype import JByte

        if size <= 0 or size > 4096:
            raise ValueError("Size must be 1-4096")

        addr = self._resolve_address(address)
        if not addr:
            raise ValueError(f"Invalid address: {address}")

        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address not in memory: {address}")

        buf = JByte[size]
        n = mem.getBytes(addr, buf)

        if n > 0:
            data = bytes([b & 0xFF for b in buf[:n]])
        else:
            data = b""

        # ASCII representation
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)

        file_offset, block = self.file_location(addr)
        return BytesResult(
            address=str(addr),
            size=len(data),
            hex=data.hex(),
            ascii=ascii_repr,
            file_offset=file_offset,
            block=block,
            provenance=self.handle.get_provenance() if include_provenance else None,
        )

    def file_location(self, addr) -> tuple[int | None, str | None]:
        """(file offset, memory block name) for a resolved Address.

        The offset comes from the loader's file-bytes mapping; it is None for
        memory with no file backing (.bss, stack, uninitialized or synthetic
        blocks).
        """
        mem = self.program.getMemory()
        block = mem.getBlock(addr)
        offset = None
        info = mem.getAddressSourceInfo(addr)
        if info is not None:
            off = int(info.getFileOffset())
            if off >= 0:
                offset = off
        return offset, (str(block.getName()) if block is not None else None)

    def list_data_types(self, query: str, limit: int = 30, max_members: int = 64) -> dict:
        """Recovered/imported data types whose name contains query (case-insensitive).

        Structures and unions list members as "offset type name"; enums list
        "NAME=value"; typedefs give their base type; function definitions
        their prototype. Pointers and arrays are skipped (they are spelled out
        inside member types). query "*" matches everything.
        """
        from ghidra.program.model.data import (
            Array,
            Enum,
            FunctionDefinition,
            Pointer,
            Structure,
            TypeDef,
            Union,
        )

        q = query.strip().lower()
        match_all = q in ("", "*")
        dtm = self.program.getDataTypeManager()
        items: list[dict] = []
        total = 0
        it = dtm.getAllDataTypes()
        while it.hasNext():
            dt = it.next()
            if isinstance(dt, (Pointer, Array)):
                continue
            name = str(dt.getName())
            if not match_all and q not in name.lower():
                continue
            total += 1
            if len(items) >= limit:
                continue
            entry: dict = {"name": name, "path": str(dt.getCategoryPath().getPath())}
            size = int(dt.getLength())
            if isinstance(dt, (Structure, Union)):
                entry["kind"] = "struct" if isinstance(dt, Structure) else "union"
                entry["size"] = size
                comps = dt.getDefinedComponents() if isinstance(dt, Structure) else dt.getComponents()
                members = []
                for c in comps:
                    fname = c.getFieldName() or f"field_0x{int(c.getOffset()):x}"
                    members.append(f"0x{int(c.getOffset()):x} {c.getDataType().getDisplayName()} {fname}")
                entry["members"] = members[:max_members]
                if len(members) > max_members:
                    entry["members_truncated"] = len(members) - max_members
            elif isinstance(dt, Enum):
                entry["kind"] = "enum"
                entry["size"] = size
                values = [f"{n}={int(dt.getValue(n))}" for n in dt.getNames()]
                entry["values"] = values[:max_members]
                if len(values) > max_members:
                    entry["values_truncated"] = len(values) - max_members
            elif isinstance(dt, TypeDef):
                entry["kind"] = "typedef"
                entry["base"] = str(dt.getBaseDataType().getDisplayName())
            elif isinstance(dt, FunctionDefinition):
                entry["kind"] = "function"
                entry["prototype"] = str(dt.getPrototypeString())
            else:
                entry["kind"] = "builtin"
                if size > 0:
                    entry["size"] = size
            items.append(entry)
        return {"query": query, "total": total, "types": items, "truncated": total > len(items)}

    def get_pcode(self, name_or_addr: str, limit: int = 400, timeout: int = 30,
                  slice_var: str | None = None) -> dict:
        """Decompiler high p-code for a function, in SSA form, one op per line.

        Ops are grouped by basic block; each block opens with a line
        "B<i> -> B<j>,B<k>:" naming its successors. Op format:
        "<addr>: <out> = <OPCODE> <in>, <in>". Every non-constant value
        is printed as <name>.<id>, where id is the decompiler's unique varnode
        id; in SSA each id is defined exactly once, so the line defining a value
        and every line using it can be found by searching for that token --
        this is the function's def-use graph. Constants print as 0x..; CALL
        targets print as the callee name; LOAD/STORE spaces by name. limit
        caps printed lines (block headers included).

        slice_var: return only the forward data-flow slice of that variable --
        every op that (transitively) consumes it, including sinks such as
        CALL/STORE/RETURN/CBRANCH. "param_2" seeds every SSA version named
        param_2; "param_2.226" seeds just that one. Propagation runs to a fixed
        point, so values carried around loops through MULTIEQUAL are followed.
        """
        from ghidra.util.task import ConsoleTaskMonitor

        func = self._find_function(name_or_addr)
        if not func:
            raise ValueError(f"Function not found: {name_or_addr}")
        result = self.decompiler.decompileFunction(func, timeout, ConsoleTaskMonitor())
        hf = result.getHighFunction() if result is not None else None
        if hf is None:
            msg = result.getErrorMessage() if result is not None else "no result"
            raise ValueError(f"Decompilation failed for {func.getName()}: {msg}")

        fm = self.program.getFunctionManager()

        def vn(v, call_target: bool = False) -> str:
            if v is None:
                return "?"
            if v.isConstant():
                mask = (1 << (8 * max(int(v.getSize()), 1))) - 1
                return f"0x{int(v.getOffset()) & mask:x}"
            if call_target and v.isAddress():
                f = fm.getFunctionAt(v.getAddress())
                if f is not None:
                    return str(f.getName())
                return str(v.getAddress())
            high = v.getHigh()
            name = None
            if high is not None:
                n = high.getName()
                if n and str(n) != "UNNAMED":
                    name = str(n)
            if name is None:
                if v.isRegister():
                    reg = self.program.getRegister(v.getAddress(), int(v.getSize()))
                    name = str(reg.getName()) if reg is not None else "reg"
                elif v.isAddress():
                    name = f"[{v.getAddress()}]"
                else:
                    name = "t"
            return f"{name}.{int(v.getUniqueId())}"

        af = self.program.getAddressFactory()

        def operand(op, mnem: str, i: int) -> str:
            v = op.getInput(i)
            if i == 0 and mnem in ("LOAD", "STORE") and v is not None and v.isConstant():
                space = af.getAddressSpace(int(v.getOffset()))
                if space is not None:
                    return str(space.getName())
            # Branch/call destinations: print the callee name or bare address.
            return vn(v, call_target=(i == 0 and mnem in ("CALL", "BRANCH", "CBRANCH")))

        # Walk basic blocks so ops print in execution order within each block
        # (hf.getPcodeOps() can list a use before its def at the same address).
        # Each block opens with "B<i> -> B<j>,B<k>:" giving the control flow.
        blocks = []  # (header, [(line, out_token | None, [in_tokens])])
        total = 0
        for block in hf.getBasicBlocks():
            succ = ",".join(f"B{block.getOut(i).getIndex()}" for i in range(block.getOutSize()))
            header = f"B{block.getIndex()}" + (f" -> {succ}" if succ else "") + ":"
            ops = []
            it = block.getIterator()
            while it.hasNext():
                op = it.next()
                total += 1
                mnem = str(op.getMnemonic())
                ins = [operand(op, mnem, i) for i in range(op.getNumInputs())]
                out = op.getOutput()
                out_tok = vn(out) if out is not None else None
                lhs = f"{out_tok} = " if out_tok else ""
                line = f"{op.getSeqnum().getTarget()}: {lhs}{mnem} {', '.join(ins)}".rstrip()
                ops.append((line, out_tok, ins))
            blocks.append((header, ops))

        result = {"function": str(func.getName()), "address": str(func.getEntryPoint())}
        keep = None
        if slice_var:
            keep, seeds = self._forward_slice(blocks, slice_var)
            if not seeds:
                raise ValueError(
                    f"No value named '{slice_var}' in {func.getName()}'s p-code; "
                    "use code(what='pcode') without a variable to see names."
                )
            result["slice"] = slice_var
            result["seeds"] = sorted(seeds)
            total = len(keep)

        lines = []
        shown = 0
        for header, ops in blocks:
            selected = [o for o in ops if keep is None or o[0] in keep]
            if not selected or len(lines) >= limit:
                continue
            lines.append(header)
            for line, _, _ in selected:
                if len(lines) >= limit:
                    break
                lines.append(line)
                shown += 1
        result.update({"ops": lines, "total_ops": total, "truncated": total > shown})
        return result

    @staticmethod
    def _forward_slice(blocks, var: str) -> tuple[set[str], set[str]]:
        """Lines (and seed tokens) of every op transitively consuming var."""
        def is_seed(tok: str) -> bool:
            return tok == var or ("." not in var and tok.rsplit(".", 1)[0] == var)

        all_ops = [o for _, ops in blocks for o in ops]
        seeds = {t for line, out, ins in all_ops for t in [out, *ins] if t and is_seed(t)}
        tracked = set(seeds)
        keep: set[str] = set()
        changed = True
        while changed:
            changed = False
            for line, out, ins in all_ops:
                if line in keep:
                    continue
                if (out and out in seeds) or any(t in tracked for t in ins):
                    keep.add(line)
                    changed = True
                    if out and out not in tracked:
                        tracked.add(out)
        return keep, seeds

    def batch_decompile(
        self,
        functions: list[str],
        timeout: int = 30,
        include_callees: bool = False,
        include_strings: bool = False,
    ) -> list[DecompiledFunction]:
        """Decompile multiple functions in one call.

        More efficient than individual decompile calls due to reduced
        MCP round-trips and shared decompiler context.

        Args:
            functions: List of function names or addresses.
            timeout: Per-function timeout in seconds.
            include_callees: Include callee lists (increases response size).
            include_strings: Include string references (increases response size).

        Returns:
            List of DecompiledFunction results (failed functions have error in code).
        """
        results = []
        for func_name in functions:
            try:
                result = self.decompile_function(
                    func_name,
                    timeout=timeout,
                    include_callees=include_callees,
                    include_strings=include_strings,
                    include_provenance=False,
                    include_refs=False,
                )
                results.append(result)
            except Exception as e:
                # Return error placeholder instead of failing entire batch
                results.append(DecompiledFunction(
                    name=func_name,
                    address="",
                    code=f"// Error: {e}",
                ))
        return results

    def get_call_graph(
        self,
        function: str,
        depth: int = 2,
        direction: str = "both",
    ) -> dict:
        """Get call graph centered on a function.

        Args:
            function: Function name or address.
            depth: How many levels to traverse (default 2).
            direction: "callers", "callees", or "both".

        Returns:
            Dict with nodes (functions) and edges ("caller -> callee" strings,
            one per distinct pair). Nodes are keyed by entry address, so
            distinct functions sharing a name stay distinct: the second and
            later get the label "name@addr". external/thunk appear only when true.
        """
        func = self._find_function(function)
        if not func:
            raise ValueError(f"Function not found: {function}")

        nodes: dict[str, dict] = {}  # entry address -> node
        labels: dict[str, str] = {}  # entry address -> label used in edges
        used_labels: set[str] = set()
        edges: list[str] = []
        edge_set: set[str] = set()
        visited = set()
        state = {"truncated": False}

        def add_edge(src: str, dst: str) -> None:
            e = f"{src} -> {dst}"
            if e not in edge_set:
                edge_set.add(e)
                edges.append(e)

        def budget_exhausted() -> bool:
            if len(nodes) >= MAX_GRAPH_NODES or len(edges) >= MAX_GRAPH_EDGES:
                state["truncated"] = True
                return True
            return False

        def add_node(f):
            addr = str(f.getEntryPoint())
            if addr not in nodes:
                name = str(f.getName())
                label = name if name not in used_labels else f"{name}@{addr}"
                used_labels.add(label)
                labels[addr] = label
                node = {"name": label, "address": addr}
                if f.isExternal():
                    node["external"] = True
                if f.isThunk():
                    node["thunk"] = True
                nodes[addr] = node
            return labels[addr]

        def traverse_callees(f, current_depth):
            if current_depth > depth:
                return
            name = add_node(f)
            if name in visited:
                return
            visited.add(name)

            for callee in f.getCalledFunctions(None):
                if budget_exhausted():
                    return
                callee_name = add_node(callee)
                add_edge(name, callee_name)
                if current_depth < depth:
                    traverse_callees(callee, current_depth + 1)

        def traverse_callers(f, current_depth):
            if current_depth > depth:
                return
            name = add_node(f)
            if name in visited:
                return
            visited.add(name)

            fm = self.program.getFunctionManager()
            rm = self.program.getReferenceManager()
            for ref in rm.getReferencesTo(f.getEntryPoint()):
                if budget_exhausted():
                    return
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller:
                    caller_name = add_node(caller)
                    add_edge(caller_name, name)
                    if current_depth < depth:
                        traverse_callers(caller, current_depth + 1)

        # Start traversal
        if direction in ("callees", "both"):
            visited.clear()
            traverse_callees(func, 0)

        if direction in ("callers", "both"):
            visited.clear()
            traverse_callers(func, 0)

        result = {
            "root": func.getName(),
            "nodes": list(nodes.values()),
            "edges": edges,
        }
        if state["truncated"]:
            result["truncated"] = True
            result["limits"] = {"max_nodes": MAX_GRAPH_NODES, "max_edges": MAX_GRAPH_EDGES}
        return result

    def get_memory_map(self) -> list[dict]:
        """Get memory layout with sections and permissions.

        Returns:
            List of memory regions with name, address, size, and permissions.
        """
        mem = self.program.getMemory()
        regions = []

        for block in mem.getBlocks():
            perms = []
            if block.isRead():
                perms.append("r")
            if block.isWrite():
                perms.append("w")
            if block.isExecute():
                perms.append("x")

            regions.append({
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": int(block.getSize()),
                "permissions": "".join(perms) or "---",
                "initialized": block.isInitialized(),
                "volatile": block.isVolatile(),
            })

        return regions

    def read_string(self, address: str) -> str:
        """Read null-terminated string at address."""
        addr = self._resolve_address(address)
        if not addr:
            raise ValueError(f"Invalid address: {address}")

        data = self.program.getListing().getDataAt(addr)
        if data and data.hasStringValue():
            return str(data.getValue())

        # Manual read
        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address not in memory: {address}")

        chars = []
        current = addr
        for _ in range(4096):  # Max string length
            try:
                b = mem.getByte(current)
                if b == 0:
                    break
                chars.append(chr(b & 0xFF))
                current = current.add(1)
            except Exception:
                break

        return "".join(chars)

    def find_bytes(self, pattern: str, limit: int = 20) -> list[dict]:
        """Search for a hex byte pattern across all initialized memory regions.

        Uses Ghidra's built-in Java findBytes() API so no full-block allocation
        occurs regardless of binary size.

        Args:
            pattern: Hex string (e.g., "deadbeef" or "de ad be ef"). Max 128 bytes.
            limit: Max results to return (default 20).

        Returns:
            List of dicts with 'address', 'section', and 'function' keys.

        Raises:
            ValueError: If pattern is empty, too long, odd-length, or invalid hex.
        """
        hex_str = pattern.replace(" ", "").lower().replace("0x", "")
        if not hex_str:
            raise ValueError("Pattern must not be empty")
        if len(hex_str) > 256:
            raise ValueError("Pattern too long (max 128 bytes / 256 hex chars)")
        if len(hex_str) % 2 != 0:
            raise ValueError("Pattern must have an even number of hex characters")
        try:
            needle = bytes.fromhex(hex_str)
        except ValueError as exc:
            raise ValueError(f"Invalid hex pattern: {exc}") from exc

        mem = self.program.getMemory()
        fm = self.program.getFunctionManager()
        blocks = [b for b in mem.getBlocks() if b.isInitialized()]
        if not blocks:
            return []

        from jpype import JByte

        # Build Java signed-byte arrays (Java byte is signed: 0xFF -> -1)
        java_needle = JByte[len(needle)]
        java_mask = JByte[len(needle)]
        for i, b in enumerate(needle):
            java_needle[i] = b if b < 128 else b - 256
            java_mask[i] = -1  # 0xFF: match all bits exactly

        results = []

        for block in blocks:
            start = block.getStart()
            end = block.getEnd()

            # Ghidra's Java findBytes avoids pulling the full block into Python
            addr = mem.findBytes(start, end, java_needle, java_mask, True, None)
            while addr is not None:
                fn = fm.getFunctionContaining(addr)
                results.append({
                    "address": str(addr),
                    "section": block.getName(),
                    "function": fn.getName() if fn else None,
                })
                if len(results) >= limit:
                    return results
                next_addr = addr.add(1)
                if next_addr.compareTo(end) > 0:
                    break
                addr = mem.findBytes(next_addr, end, java_needle, java_mask, True, None)

        return results

    def entropy_map(self) -> list[dict]:
        """Compute Shannon entropy per memory section.

        Sections with entropy > 7.0 are likely encrypted or compressed.
        Sections with entropy < 1.0 are mostly zeros or padding.

        Returns:
            List of dicts with 'name', 'size', 'entropy', and 'note' keys,
            sorted by entropy descending.
        """
        import math

        from jpype import JByte
        mem = self.program.getMemory()
        results = []

        for block in mem.getBlocks():
            if not block.isInitialized():
                results.append({
                    "name": block.getName(),
                    "size": int(block.getSize()),
                    "entropy": None,
                    "note": "uninitialized",
                })
                continue

            size = int(block.getSize())
            # Sample up to 64KB for large sections (representative)
            sample_size = min(size, 65536)
            buf = JByte[sample_size]
            n = mem.getBytes(block.getStart(), buf)
            if n <= 0:
                results.append({
                    "name": block.getName(),
                    "size": size,
                    "entropy": None,
                    "note": "read error",
                })
                continue
            data = bytes([b & 0xFF for b in buf[:n]])

            counts = [0] * 256
            for b in data:
                counts[b] += 1
            entropy = 0.0
            for c in counts:
                if c > 0:
                    p = c / len(data)  # use actual bytes read, not sample_size
                    entropy -= p * math.log2(p)

            entropy = round(entropy, 3)
            if entropy > 7.5:
                note = "likely encrypted/packed"
            elif entropy > 7.0:
                note = "high entropy"
            elif entropy < 1.0:
                note = "mostly zeros/padding"
            else:
                note = ""

            row = {"name": block.getName(), "size": size, "entropy": entropy}
            if note:
                row["note"] = note
            results.append(row)

        results.sort(key=lambda r: (r["entropy"] or 0), reverse=True)
        return results

    def detect_embedded_runtime(self, compact: bool = True) -> dict:
        """Detect embedded runtime payloads within the binary.

        Scans for magic byte signatures associated with common embedded runtime
        formats. For each detected runtime, reports the type, confidence, and the
        recommended strategy for finding strings within it.

        Strategies:
          - "external_tools": payload is compressed; raw scanning is useless.
            Use external tools (e.g. extract_bunfs.py for Bun).
          - "search_payload": payload is uncompressed; use extract_strings_from_blob()
            with the returned payload_offset.
          - "unpack_first": payload is packed (e.g. UPX); unpack before scanning.

        Args:
            compact: Return minimal output (detected + runtimes list). If False,
                     adds magic_address and section per runtime entry.
        """
        mem = self.program.getMemory()
        runtimes = []

        for sig in _RUNTIME_SIGNATURES:
            magic_address: str | None = None
            hit_section: str | None = None
            confidence = sig["confidence"]

            # For v8_snapshot: check symbol table first (more stable than magic bytes)
            if sig.get("symbol"):
                st = self.program.getSymbolTable()
                sym_found = False
                for sym in st.getAllSymbols(True):
                    if sym.getName() == sig["symbol"]:
                        magic_address = str(sym.getAddress())
                        confidence = "high"  # symbol match -> upgrade to high
                        block = mem.getBlock(sym.getAddress())
                        hit_section = block.getName() if block else None
                        sym_found = True
                        break

                if not sym_found:
                    hits = self.find_bytes(sig["magic"], limit=1)
                    if hits:
                        magic_address = hits[0]["address"]
                        hit_section = hits[0].get("section")
                        # confidence stays at sig default ("medium" for v8 magic-only)
            else:
                hits = self.find_bytes(sig["magic"], limit=1)
                if hits:
                    magic_address = hits[0]["address"]
                    hit_section = hits[0].get("section")

            if magic_address is None:
                continue

            # Confidence adjustments -- low-confidence hits are omitted entirely
            if sig.get("section_adjust") and hit_section == ".text":
                continue  # electron_asar in .text: likely false positive
            if sig.get("strtab_fp") and hit_section == ".strtab":
                continue  # node_sea fuse in .strtab: likely just the symbol name

            payload_offset = magic_address if sig["strategy"] == "search_payload" else None
            rt = EmbeddedRuntime(
                type=sig["type"],
                confidence=confidence,
                strategy=sig["strategy"],
                payload_offset=payload_offset,
            )

            if compact:
                entry = rt.model_dump(exclude_none=True)
            else:
                entry = rt.model_dump(exclude_none=True)
                entry["magic_address"] = magic_address
                if hit_section:
                    entry["section"] = hit_section

            runtimes.append(entry)

        return {"detected": len(runtimes) > 0, "runtimes": runtimes}

    def search_strings_deep(
        self,
        query: str,
        min_length: int = 4,
        sections: list[str] | None = None,
        skip_high_entropy: bool = False,
        compact: bool = True,
        limit: int = 20,
    ) -> list[dict]:
        """Raw memory scan for ASCII strings, bypassing Ghidra's defined-string list.

        Unlike search_strings() which only finds strings Ghidra has already defined,
        this scans raw memory blocks for printable ASCII runs -- useful for lightly-
        analyzed binaries or sections with no defined data.

        For compressed payloads (Bun/BunFS), this tool won't find readable strings --
        use detect_embedded_runtime() first. For uncompressed/lightly-compressed
        payloads (ASAR, Node SEA), pass the sections parameter or use
        extract_strings_from_blob().

        Args:
            query: Case-insensitive substring filter.
            min_length: Minimum string length (default 4).
            sections: Only scan these sections (default: all initialized sections).
            skip_high_entropy: Skip sections with Shannon entropy > 7.5 (default False).
            compact: Return [{value, address, section}] (default True). If False,
                     returns full value + is_defined + up to 5 refs per hit.
            limit: Max results (default 20).
        """
        from jpype import JByte

        mem = self.program.getMemory()
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        listing = self.program.getListing()

        high_entropy_sections: set[str] = set()
        if skip_high_entropy:
            for entry in self.entropy_map():
                if entry.get("entropy") is not None and entry["entropy"] > 7.5:
                    high_entropy_sections.add(entry["name"])

        results: list[dict] = []
        query_lower = query.lower()
        CHUNK = 65536

        for block in mem.getBlocks():
            if not block.isInitialized():
                continue

            block_name = block.getName()

            if skip_high_entropy and block_name in high_entropy_sections:
                continue

            if sections is not None and block_name not in sections:
                continue

            # Read entire block in chunks to avoid OOM on large sections
            size = int(block.getSize())
            all_bytes = bytearray()
            offset = 0
            while offset < size:
                n_read = min(CHUNK, size - offset)
                buf = JByte[n_read]
                n = mem.getBytes(block.getStart().add(offset), buf)
                if n <= 0:
                    break
                all_bytes.extend(b & 0xFF for b in buf[:n])
                offset += n

            data = bytes(all_bytes)
            data_len = len(data)

            # Single-pass printable ASCII run scanner
            i = 0
            while i < data_len:
                if 32 <= data[i] < 127:
                    start = i
                    while i < data_len and 32 <= data[i] < 127:
                        i += 1
                    length = i - start
                    if length >= min_length:
                        val = data[start:i].decode("ascii")
                        if query_lower in val.lower():
                            str_addr = block.getStart().add(start)

                            if compact:
                                results.append({
                                    "value": val[:80],
                                    "address": str(str_addr),
                                    "section": block_name,
                                })
                            else:
                                is_defined = False
                                try:
                                    d = listing.getDefinedDataAt(str_addr)
                                    is_defined = d is not None and d.hasStringValue()
                                except Exception:
                                    pass

                                refs: list[str] = []
                                try:
                                    for ref in rm.getReferencesTo(str_addr):
                                        func = fm.getFunctionContaining(ref.getFromAddress())
                                        if func:
                                            refs.append(func.getName())
                                        if len(refs) >= 5:
                                            break
                                    refs = list(set(refs))[:5]
                                except Exception:
                                    pass

                                results.append({
                                    "value": val,
                                    "address": str(str_addr),
                                    "section": block_name,
                                    "is_defined": is_defined,
                                    "refs": refs,
                                })

                            if len(results) >= limit:
                                return results
                else:
                    i += 1

        return results

    def batch_search_strings(
        self,
        queries: list[str],
        mode: str = "deep",
        min_length: int = 4,
        skip_high_entropy: bool = False,
        compact: bool = True,
        limit_per_query: int = 5,
    ) -> dict:
        """Search for multiple string patterns in one call.

        For mode="deep": reads all memory blocks once and scans all queries
        simultaneously -- more efficient than N separate search_strings_deep() calls.
        For mode="indexed": iterates Ghidra's defined strings once across all queries.
        Entropy map is computed at most once for the batch, regardless of query count.

        Args:
            queries: List of search patterns (max 20).
            mode: "deep" (raw memory scan, default) or "indexed" (defined strings only).
            min_length: Minimum string length (default 4).
            skip_high_entropy: Skip sections with entropy > 7.5 (default False).
            compact: Return {query: count} (default True). If False, returns
                     {query: [{value, address, section}]} -- compact-format hits.
            limit_per_query: Max hits per query (default 5).

        Raises:
            ValueError: If more than 20 queries are provided.
        """
        if len(queries) > 20:
            raise ValueError("Maximum 20 queries per batch")

        results_hits: dict[str, list[dict]] = {q: [] for q in queries}
        queries_lower = {q: q.lower() for q in queries}

        if mode == "indexed":
            try:
                from ghidra.program.util import DefinedStringIterator
                data_iter = DefinedStringIterator.forProgram(self.program)
            except (ImportError, AttributeError):
                from ghidra.program.util import DefinedDataIterator
                data_iter = DefinedDataIterator.definedStrings(self.program)

            mem = self.program.getMemory()
            for data in data_iter:
                try:
                    val = str(data.getValue())
                    addr = data.getAddress()
                    block = mem.getBlock(addr)
                    section = block.getName() if block else None
                    truncated = val[:80]
                    val_lower = val.lower()
                    for q, q_lower in queries_lower.items():
                        if q_lower in val_lower and len(results_hits[q]) < limit_per_query:
                            results_hits[q].append({
                                "value": truncated,
                                "address": str(addr),
                                "section": section,
                            })
                except Exception:
                    continue

            if compact:
                return {q: len(hits) for q, hits in results_hits.items()}
            return results_hits

        # mode == "deep": single-pass memory read, multi-query scan
        from jpype import JByte

        # Compute entropy once for the entire batch
        high_entropy_sections: set[str] = set()
        if skip_high_entropy:
            for entry in self.entropy_map():
                if entry.get("entropy") is not None and entry["entropy"] > 7.5:
                    high_entropy_sections.add(entry["name"])

        mem = self.program.getMemory()
        CHUNK = 65536

        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            block_name = block.getName()
            if skip_high_entropy and block_name in high_entropy_sections:
                continue

            # Early exit: all queries at limit
            if all(len(hits) >= limit_per_query for hits in results_hits.values()):
                break

            size = int(block.getSize())
            all_bytes = bytearray()
            offset = 0
            while offset < size:
                n_read = min(CHUNK, size - offset)
                buf = JByte[n_read]
                n = mem.getBytes(block.getStart().add(offset), buf)
                if n <= 0:
                    break
                all_bytes.extend(b & 0xFF for b in buf[:n])
                offset += n

            data = bytes(all_bytes)
            data_len = len(data)

            i = 0
            while i < data_len:
                if 32 <= data[i] < 127:
                    start = i
                    while i < data_len and 32 <= data[i] < 127:
                        i += 1
                    length = i - start
                    if length >= min_length:
                        val = data[start:i].decode("ascii")
                        val_lower = val.lower()
                        for q, q_lower in queries_lower.items():
                            if q_lower in val_lower and len(results_hits[q]) < limit_per_query:
                                str_addr = block.getStart().add(start)
                                results_hits[q].append({
                                    "value": val[:80],
                                    "address": str(str_addr),
                                    "section": block_name,
                                })
                else:
                    i += 1

        if compact:
            return {q: len(hits) for q, hits in results_hits.items()}
        return results_hits

    def extract_strings_from_blob(
        self,
        offset: str,
        size: int,
        query: str = "",
        min_length: int = 6,
        compact: bool = True,
        limit: int = 20,
    ) -> list[dict]:
        """Extract strings from a raw memory region (no decompression).

        Useful for scanning uncompressed embedded payloads like ASAR or Node SEA.
        Pass the payload_offset returned by detect_embedded_runtime() as the offset.

        For compressed payloads (Bun/BunFS), this won't find readable strings --
        use external tools (extract_bunfs.py) instead.

        Args:
            offset: Start address (hex, e.g., "0x1b20000").
            size: Region size in bytes (max 50MB).
            query: Case-insensitive filter (default: return all strings).
            min_length: Minimum string length (default 6).
            compact: Return [{value, address}] (default True). If False, adds blob_offset
                     (relative offset from region start as hex).
            limit: Max results (default 20).

        Raises:
            ValueError: If size exceeds 50MB or offset is invalid.
        """
        from jpype import JByte

        if size <= 0:
            raise ValueError("size must be positive")
        if size > 50 * 1024 * 1024:
            raise ValueError("size exceeds 50MB limit")

        addr = self._resolve_address(offset)
        if not addr:
            raise ValueError(f"Invalid address: {offset}")

        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address not in memory: {offset}")

        # Read region in chunks
        CHUNK = 65536
        all_bytes = bytearray()
        bytes_read = 0
        while bytes_read < size:
            n_read = min(CHUNK, size - bytes_read)
            buf = JByte[n_read]
            read_addr = addr.add(bytes_read)
            if not mem.contains(read_addr):
                break
            n = mem.getBytes(read_addr, buf)
            if n <= 0:
                break
            all_bytes.extend(b & 0xFF for b in buf[:n])
            bytes_read += n

        data = bytes(all_bytes)
        query_lower = query.lower() if query else ""
        results: list[dict] = []

        i = 0
        data_len = len(data)
        while i < data_len:
            if 32 <= data[i] < 127:
                start = i
                while i < data_len and 32 <= data[i] < 127:
                    i += 1
                length = i - start
                if length >= min_length:
                    val = data[start:i].decode("ascii")
                    if not query_lower or query_lower in val.lower():
                        str_addr = addr.add(start)
                        if compact:
                            results.append({
                                "value": val[:80],
                                "address": str(str_addr),
                            })
                        else:
                            results.append({
                                "value": val,
                                "address": str(str_addr),
                                "blob_offset": hex(start),
                            })
                        if len(results) >= limit:
                            return results
            else:
                i += 1

        return results


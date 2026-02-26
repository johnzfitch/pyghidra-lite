"""Ghidra tool implementations for pyghidra-lite."""

import logging
import time
from typing import TYPE_CHECKING

from pyghidra_lite.backend import ProgramHandle, compute_stable_id
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

if TYPE_CHECKING:
    from ghidra.program.model.listing import Function

    from pyghidra_lite.backend import GhidraBackend

logger = logging.getLogger(__name__)

# Cache TTL in seconds (functions don't change during analysis session)
CACHE_TTL = 300

# Capability tags for common APIs
CAPABILITY_TAGS = {
    # Crypto
    "crypto": ["aes", "des", "rsa", "sha", "md5", "encrypt", "decrypt", "cipher", "hash", "hmac",
               "ssl", "tls", "crypto", "pkcs", "x509", "certificate"],
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


def get_capability_tags(name: str) -> list[str]:
    """Get capability tags for an import/export name."""
    name_lower = name.lower()
    tags = []
    for tag, keywords in CAPABILITY_TAGS.items():
        if any(kw in name_lower for kw in keywords):
            tags.append(tag)
    return tags


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
            code = result.decompiledFunction.getC()
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
        """Resolve a name or address string to an Address."""
        af = self.program.getAddressFactory()

        # Try as address
        try:
            addr_str = name_or_addr.replace("0x", "")
            addr = af.getAddress(addr_str)
            if addr:
                return addr
        except Exception:
            pass

        # Try as symbol
        st = self.program.getSymbolTable()
        for sym in st.getAllSymbols(True):
            if sym.getName().lower() == name_or_addr.lower():
                return sym.getAddress()

        return None

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

                # Truncate very long strings to save tokens
                truncated_val = val[:500] if len(val) > 500 else val
                results.append(StringXref(
                    value=truncated_val,
                    address=str(data.getAddress()),
                    refs=refs,
                    looks_like=looks_like,
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

        return BytesResult(
            address=str(addr),
            size=len(data),
            hex=data.hex(),
            ascii=ascii_repr,
            provenance=self.handle.get_provenance() if include_provenance else None,
        )

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
            Dict with nodes (functions) and edges (calls).
        """
        func = self._find_function(function)
        if not func:
            raise ValueError(f"Function not found: {function}")

        nodes = {}
        edges = []
        visited = set()

        def add_node(f):
            name = f.getName()
            if name not in nodes:
                nodes[name] = {
                    "name": name,
                    "address": str(f.getEntryPoint()),
                    "is_external": f.isExternal(),
                    "is_thunk": f.isThunk(),
                }
            return name

        def traverse_callees(f, current_depth):
            if current_depth > depth:
                return
            name = add_node(f)
            if name in visited:
                return
            visited.add(name)

            for callee in f.getCalledFunctions(None):
                callee_name = add_node(callee)
                edges.append({"from": name, "to": callee_name, "type": "calls"})
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
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller:
                    caller_name = add_node(caller)
                    edges.append({"from": caller_name, "to": name, "type": "calls"})
                    if current_depth < depth:
                        traverse_callers(caller, current_depth + 1)

        # Start traversal
        if direction in ("callees", "both"):
            visited.clear()
            traverse_callees(func, 0)

        if direction in ("callers", "both"):
            visited.clear()
            traverse_callers(func, 0)

        return {
            "root": func.getName(),
            "nodes": list(nodes.values()),
            "edges": edges,
        }

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

        # Build Java signed-byte arrays (Java byte is signed: 0xFF → -1)
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

            results.append({
                "name": block.getName(),
                "size": size,
                "entropy": entropy,
                "note": note,
            })

        results.sort(key=lambda r: (r["entropy"] or 0), reverse=True)
        return results


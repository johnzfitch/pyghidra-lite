"""Ghidra tool implementations for pyghidra-lite."""

import logging
import re
from typing import TYPE_CHECKING

from pyghidra_lite.backend import ProgramHandle, compute_stable_id
from pyghidra_lite.models import (
    BytesResult,
    CodeMatch,
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

logger = logging.getLogger(__name__)

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
    """Tool implementations using Ghidra APIs."""

    def __init__(self, handle: ProgramHandle):
        self.handle = handle
        self.program = handle.program
        self.decompiler = handle.decompiler

    def list_functions(
        self,
        pattern: str = "",
        limit: int = 50,
        sort_by: str = "name",
        include_thunks: bool = False,
        include_external: bool = False,
    ) -> list[FunctionInfo]:
        """List functions with metadata annotations."""
        fm = self.program.getFunctionManager()
        rm = self.program.getReferenceManager()

        results = []
        for func in fm.getFunctions(True):
            func: Function
            if not include_external and func.isExternal():
                continue
            if not include_thunks and func.isThunk():
                continue
            if pattern and pattern.lower() not in func.getName().lower():
                continue

            # Compute metadata
            entry = func.getEntryPoint()
            refs_in = len(list(rm.getReferencesTo(entry)))
            refs_out = len(list(func.getCalledFunctions(None)))

            # Check for strings
            has_strings = False
            try:
                body = func.getBody()
                for addr in body.getAddresses(True):
                    refs = rm.getReferencesFrom(addr)
                    for ref in refs:
                        data = self.program.getListing().getDataAt(ref.getToAddress())
                        if data and data.hasStringValue():
                            has_strings = True
                            break
                    if has_strings:
                        break
            except Exception:
                pass

            results.append(FunctionInfo(
                name=func.getName(),
                address=str(entry),
                stable_id=compute_stable_id(self.handle.unit_id, str(entry)),
                size=int(func.getBody().getNumAddresses()),
                refs_in=refs_in,
                refs_out=refs_out,
                has_strings=has_strings,
                is_library=func.getName().startswith("FID_"),  # FIDB convention
                is_thunk=func.isThunk(),
            ))

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

    def decompile_function(self, name_or_addr: str, timeout: int = 30) -> DecompiledFunction:
        """Decompile a function."""
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

        # Extract callees and strings
        callees = [f.getName() for f in func.getCalledFunctions(None)]
        strings_used = self._get_function_strings(func)

        entry = func.getEntryPoint()
        rm = self.program.getReferenceManager()

        return DecompiledFunction(
            name=func.getName(),
            address=str(entry),
            stable_id=compute_stable_id(self.handle.unit_id, str(entry)),
            signature=signature,
            code=code,
            refs_in=len(list(rm.getReferencesTo(entry))),
            refs_out=len(callees),
            callees=callees if callees else None,
            strings_used=strings_used if strings_used else None,
            provenance=self.handle.get_provenance(),
        )

    def _find_function(self, name_or_addr: str) -> "Function | None":
        """Find a function by name or address."""
        fm = self.program.getFunctionManager()

        # Try as address first
        try:
            addr = self.program.getAddressFactory().getAddress(name_or_addr.replace("0x", ""))
            func = fm.getFunctionAt(addr)
            if func:
                return func
        except Exception:
            pass

        # Search by name
        for func in fm.getFunctions(True):
            if func.getName() == name_or_addr:
                return func

        # Case-insensitive search
        for func in fm.getFunctions(True):
            if func.getName().lower() == name_or_addr.lower():
                return func

        return None

    def _get_function_strings(self, func: "Function") -> list[str]:
        """Get string literals referenced by a function."""
        strings = []
        rm = self.program.getReferenceManager()
        try:
            body = func.getBody()
            for addr in body.getAddresses(True):
                refs = rm.getReferencesFrom(addr)
                for ref in refs:
                    data = self.program.getListing().getDataAt(ref.getToAddress())
                    if data and data.hasStringValue():
                        try:
                            val = str(data.getValue())
                            if val and len(val) > 1:
                                strings.append(val)
                        except Exception:
                            pass
        except Exception:
            pass
        return list(set(strings))[:20]  # Limit to 20

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

                results.append(StringXref(
                    value=val,
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
        rm = self.program.getReferenceManager()
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

    def read_bytes(self, address: str, size: int) -> BytesResult:
        """Read raw bytes at an address."""
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
            provenance=self.handle.get_provenance(),
        )

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

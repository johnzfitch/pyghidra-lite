"""Hermes bytecode analysis tools for React Native apps."""

import logging
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)

# Hermes magic bytes
HERMES_MAGIC = [
    b'\xc6\x1f\xbc\x03',  # Older versions
    b'\x1f\xbc\x03\xc6',  # Endian variant
    b'HBC',               # Some versions
]

# Hermes opcodes (partial list of common ones)
HERMES_OPCODES = {
    0x00: "Unreachable",
    0x01: "NewObject",
    0x02: "NewObjectWithBuffer",
    0x03: "NewArray",
    0x04: "NewArrayWithBuffer",
    0x05: "Mov",
    0x06: "MovLong",
    0x07: "Negate",
    0x08: "Not",
    0x09: "BitNot",
    0x0A: "TypeOf",
    0x0B: "Eq",
    0x0C: "StrictEq",
    0x0D: "Neq",
    0x0E: "StrictNeq",
    0x0F: "Less",
    0x10: "LessEq",
    0x11: "Greater",
    0x12: "GreaterEq",
    0x13: "Add",
    0x14: "AddN",
    0x15: "Sub",
    0x16: "SubN",
    0x17: "Mul",
    0x18: "MulN",
    0x19: "Div",
    0x1A: "DivN",
    0x1B: "Mod",
    0x1C: "BitAnd",
    0x1D: "BitOr",
    0x1E: "BitXor",
    0x1F: "LShift",
    0x20: "RShift",
    0x21: "URshift",
    0x30: "Call",
    0x31: "Construct",
    0x32: "Call1",
    0x33: "CallDirect",
    0x34: "Call2",
    0x35: "Call3",
    0x36: "Call4",
    0x40: "LoadConstString",
    0x41: "LoadConstStringLongIndex",
    0x42: "LoadConstUInt8",
    0x43: "LoadConstInt",
    0x44: "LoadConstDouble",
    0x45: "LoadConstZero",
    0x46: "LoadConstUndefined",
    0x47: "LoadConstNull",
    0x48: "LoadConstTrue",
    0x49: "LoadConstFalse",
    0x50: "GetById",
    0x51: "GetByIdShort",
    0x52: "TryGetById",
    0x53: "PutById",
    0x54: "TryPutById",
    0x55: "PutNewOwnById",
    0x56: "PutNewOwnByIdShort",
    0x60: "GetByVal",
    0x61: "PutByVal",
    0x62: "DelByVal",
    0x63: "PutOwnByVal",
    0x70: "Jmp",
    0x71: "JmpLong",
    0x72: "JmpTrue",
    0x73: "JmpTrueLong",
    0x74: "JmpFalse",
    0x75: "JmpFalseLong",
    0x76: "JmpUndefined",
    0x77: "JmpUndefinedLong",
    0x80: "Ret",
    0x81: "Catch",
    0x82: "Throw",
    0x83: "ThrowIfEmpty",
    0x90: "CreateClosure",
    0x91: "CreateClosureLongIndex",
    0x92: "CreateGeneratorClosure",
    0x93: "CreateAsyncClosure",
    0xA0: "LoadParam",
    0xA1: "LoadParamLong",
    0xA2: "CoerceThisNS",
    0xA3: "LoadThisNS",
    0xB0: "CreateEnvironment",
    0xB1: "StoreToEnvironment",
    0xB2: "StoreToEnvironmentL",
    0xB3: "LoadFromEnvironment",
    0xB4: "LoadFromEnvironmentL",
    0xC0: "GetGlobalObject",
    0xC1: "GetNewTarget",
    0xC2: "DeclareGlobalVar",
    0xC3: "CreateRegExp",
    0xD0: "SwitchImm",
    0xE0: "NewObjectWithParent",
    0xE1: "CreateThis",
    0xE2: "SelectObject",
}


@dataclass
class HermesFunction:
    """Hermes bytecode function."""
    id: int
    name: str | None
    offset: int
    size: int
    num_params: int
    num_registers: int
    flags: int = 0


@dataclass
class HermesString:
    """String from Hermes string table."""
    id: int
    value: str
    is_utf16: bool = False


@dataclass
class HermesInfo:
    """Summary of Hermes bytecode file."""
    is_hermes: bool
    version: int | None = None
    num_functions: int = 0
    num_strings: int = 0
    bundle_size: int = 0
    has_debug_info: bool = False
    source_hash: str | None = None


def is_hermes_bytecode(data: bytes) -> bool:
    """Check if data starts with Hermes magic."""
    if len(data) < 4:
        return False
    for magic in HERMES_MAGIC:
        if data[:len(magic)] == magic:
            return True
    # Also check for HBC header patterns
    return len(data) > 8 and (b'HBC' in data[:64] or data[4:8] == b'\x00\x00\x00\x00')


def parse_hermes_header(data: bytes) -> dict | None:
    """Parse Hermes bytecode header."""
    if len(data) < 64:
        return None

    try:
        # Hermes header format varies by version
        # Try to extract basic info
        magic = data[:4]
        version = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else None

        return {
            "magic": magic.hex(),
            "version": version,
        }
    except Exception:
        return None


class HermesTools:
    """Hermes bytecode analysis tools.

    Note: Ghidra doesn't natively support Hermes, so this provides
    basic analysis. For full Hermes RE, consider hermes-dec or hbctool.
    """

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program
        self._strings_cache: list[str] | None = None

    def is_hermes(self) -> bool:
        """Check if this might be Hermes bytecode or contain Hermes."""
        # Check metadata
        fmt = self.handle.metadata.get("Executable Format", "")
        if "hermes" in fmt.lower():
            return True

        # Check for Hermes strings
        strings = self._find_hermes_strings()
        return len(strings) > 0

    def _find_hermes_strings(self) -> list[str]:
        """Find strings that indicate Hermes bytecode."""
        if self._strings_cache is not None:
            return self._strings_cache

        hermes_indicators = [
            "HermesInternal",
            "__hermes",
            "HBC",
            "hermes.bytecode",
            "react-native",
            "ReactNative",
            "__fbBatchedBridge",
            "nativeModuleProxy",
        ]

        found = []
        try:
            from ghidra.program.util import DefinedDataIterator
            data_iter = DefinedDataIterator.definedStrings(self.program)

            for data in data_iter:
                try:
                    val = str(data.getValue())
                    for indicator in hermes_indicators:
                        if indicator in val:
                            found.append(val)
                            break
                except Exception:
                    pass

                if len(found) > 10:
                    break
        except Exception:
            pass

        self._strings_cache = found
        return found

    def get_hermes_info(self) -> HermesInfo:
        """Get Hermes bytecode summary."""
        hermes_strings = self._find_hermes_strings()

        if not hermes_strings:
            return HermesInfo(is_hermes=False)

        # Try to find embedded HBC data
        mem = self.program.getMemory()
        total_size = sum(int(b.getSize()) for b in mem.getBlocks())

        return HermesInfo(
            is_hermes=True,
            num_strings=len(hermes_strings),
            bundle_size=total_size,
        )

    def find_js_functions(self, pattern: str = "", limit: int = 50) -> list[dict]:
        """Find potential JavaScript function names in strings.

        Args:
            pattern: Filter by name
            limit: Max results
        """
        results = []

        try:
            from ghidra.program.util import DefinedDataIterator
            data_iter = DefinedDataIterator.definedStrings(self.program)

            # JS function patterns
            js_patterns = [
                "function",
                "=>",
                "async",
                "export",
                "import",
                "class",
                "render",
                "Component",
                "useState",
                "useEffect",
                "dispatch",
                "reducer",
            ]

            for data in data_iter:
                try:
                    val = str(data.getValue())

                    if pattern and pattern.lower() not in val.lower():
                        continue

                    # Check if it looks like JS code or function name
                    is_js = any(p in val for p in js_patterns)
                    if is_js or (val.isidentifier() and len(val) > 2):
                        results.append({
                            "value": val[:200],  # Truncate long strings
                            "address": str(data.getAddress()),
                            "looks_like": "js_code" if is_js else "identifier",
                        })

                    if len(results) >= limit:
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return results

    def find_react_components(self, limit: int = 50) -> list[dict]:
        """Find React component names.

        Args:
            limit: Max results
        """
        results = []

        try:
            from ghidra.program.util import DefinedDataIterator
            data_iter = DefinedDataIterator.definedStrings(self.program)

            for data in data_iter:
                try:
                    val = str(data.getValue())

                    # React components are PascalCase
                    if (val and val[0].isupper() and
                        len(val) > 2 and
                        val.isidentifier() and
                        any(c.islower() for c in val)):

                        # Common component patterns
                        is_component = any(suffix in val for suffix in [
                            "Screen", "View", "Component", "Provider",
                            "Container", "Modal", "Button", "Input",
                            "List", "Item", "Card", "Header", "Footer",
                            "Navigation", "Navigator", "Route", "Page",
                        ])

                        if is_component or val.endswith(("Screen", "View", "Component")):
                            results.append({
                                "name": val,
                                "address": str(data.getAddress()),
                                "type": "component",
                            })

                    if len(results) >= limit:
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return results

    def extract_api_endpoints(self, limit: int = 50) -> list[dict]:
        """Find API endpoints and URLs in the bundle.

        Args:
            limit: Max results
        """
        results = []

        try:
            from ghidra.program.util import DefinedDataIterator
            data_iter = DefinedDataIterator.definedStrings(self.program)

            for data in data_iter:
                try:
                    val = str(data.getValue())

                    endpoint_type = None
                    if val.startswith(("http://", "https://", "wss://", "ws://")):
                        endpoint_type = "url"
                    elif val.startswith("/api/") or "/api/" in val or val.startswith("/v1/") or val.startswith("/v2/"):
                        endpoint_type = "api_path"
                    elif ".com/" in val or ".io/" in val or ".net/" in val:
                        endpoint_type = "domain"

                    if endpoint_type:
                        results.append({
                            "value": val,
                            "type": endpoint_type,
                            "address": str(data.getAddress()),
                        })

                    if len(results) >= limit:
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return results

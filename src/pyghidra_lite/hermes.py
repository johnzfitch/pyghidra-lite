"""Hermes bytecode inspection tools for React Native apps."""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyghidra_lite.backend import ProgramHandle

logger = logging.getLogger(__name__)


@dataclass
class HermesInfo:
    """Summary of Hermes bytecode file."""
    is_hermes: bool
    version: int | None = None
    num_functions: int = 0
    num_strings: int = 0
    bundle_size: int = 0
    has_debug_info: bool = False


class HermesTools:
    """Hermes bytecode inspection tools.

    Note: Ghidra doesn't natively support Hermes, so this provides
    basic analysis via string heuristics. For full Hermes RE, consider
    hermes-dec or hbctool.
    """

    def __init__(self, handle: "ProgramHandle"):
        self.handle = handle
        self.program = handle.program
        self._strings_cache: list[str] | None = None

    def is_hermes(self) -> bool:
        """Check if this might contain Hermes bytecode."""
        fmt = self.handle.metadata.get("Executable Format", "")
        if "hermes" in fmt.lower():
            return True
        return len(self._find_hermes_strings()) > 0

    def _find_hermes_strings(self) -> list[str]:
        """Find strings that indicate Hermes bytecode."""
        if self._strings_cache is not None:
            return self._strings_cache

        indicators = [
            "HermesInternal", "__hermes", "HBC", "hermes.bytecode",
            "react-native", "ReactNative", "__fbBatchedBridge", "nativeModuleProxy",
        ]

        found = []
        try:
            from ghidra.program.util import DefinedDataIterator
            data_iter = DefinedDataIterator.definedStrings(self.program)

            for data in data_iter:
                try:
                    val = str(data.getValue())
                    for indicator in indicators:
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

        mem = self.program.getMemory()
        total_size = sum(int(b.getSize()) for b in mem.getBlocks())

        return HermesInfo(
            is_hermes=True,
            num_strings=len(hermes_strings),
            bundle_size=total_size,
        )

    def find_react_components(self, limit: int = 50) -> list[dict]:
        """Find React component names."""
        results = []

        try:
            from ghidra.program.util import DefinedDataIterator
            data_iter = DefinedDataIterator.definedStrings(self.program)

            component_suffixes = (
                "Screen", "View", "Component", "Provider", "Container",
                "Modal", "Button", "Input", "List", "Item", "Card",
                "Header", "Footer", "Navigation", "Navigator", "Route", "Page",
            )

            for data in data_iter:
                try:
                    val = str(data.getValue())
                    if (val and val[0].isupper() and len(val) > 2
                            and val.isidentifier()
                            and any(c.islower() for c in val)
                            and val.endswith(component_suffixes)):
                        results.append({
                            "name": val,
                            "address": str(data.getAddress()),
                        })
                    if len(results) >= limit:
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return results

    def extract_api_endpoints(self, limit: int = 50) -> list[dict]:
        """Find API endpoints and URLs in the bundle."""
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
                    elif val.startswith("/api/") or "/api/" in val or val.startswith(("/v1/", "/v2/")):
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

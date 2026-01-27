#!/usr/bin/env python3
"""Basic usage example for pyghidra-lite as a Python library."""

import asyncio
from pathlib import Path

from pyghidra_lite.analyzer import GhidraAnalyzer


async def main():
    """Analyze a binary and print function information."""
    # Initialize analyzer
    analyzer = GhidraAnalyzer(
        project_name="example_project",
        project_dir=Path.home() / ".cache" / "pyghidra-examples"
    )

    # Load a binary
    binary_path = "/path/to/your/binary"
    analyzer.load(binary_path, profile="fast", analyze=True)

    print(f"Loaded: {analyzer.info['name']}")
    print(f"Analyzed: {analyzer.info['analyzed']}")

    # List functions
    functions = analyzer.functions(limit=10)
    print(f"\nFound {len(functions)} functions:")
    for func in functions:
        print(f"  {func.name} @ {func.address}")

    # Decompile a specific function
    if functions:
        func_name = functions[0].name
        print(f"\nDecompiling {func_name}...")
        result = analyzer.decompile(func_name)
        print(result.code[:500])  # Print first 500 chars

    # Search for strings
    strings = analyzer.strings("http", limit=5)
    print(f"\nFound {len(strings)} strings with 'http':")
    for s in strings:
        print(f"  {s.value[:50]}... @ {s.address}")
        print(f"    Referenced by: {', '.join(s.refs[:3])}")

    # Clean up
    analyzer.close()


if __name__ == "__main__":
    asyncio.run(main())

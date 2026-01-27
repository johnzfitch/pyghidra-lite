# pyghidra-lite MCP Server - Release Guide

## Overview

pyghidra-lite is a Model Context Protocol (MCP) server that provides Ghidra-based reverse engineering capabilities to AI assistants. It supports iOS (Mach-O), Linux (ELF), and game binary analysis with specialized tools for Swift, Objective-C, and React Native (Hermes).

## MCP Compliance

This server complies with the [Model Context Protocol Specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25), jointly maintained by OpenAI and Anthropic under the Linux Foundation's Agentic AI Foundation.

### Protocol Features

✅ **JSON-RPC 2.0** message format
✅ **Stateful connections** with capability negotiation
✅ **Tools**: 40+ reverse engineering tools exposed via MCP
✅ **Resources**: Binary analysis results and metadata
✅ **Transport**: stdio (default) and SSE (Server-Sent Events)
✅ **Security**: Path-based access controls and explicit tool consent

## Installation

### Prerequisites

- Python 3.11 or later
- Ghidra installed at `/opt/ghidra` or set `GHIDRA_INSTALL_DIR`
- Java Runtime Environment (for Ghidra)

### Install from PyPI

```bash
pip install pyghidra-lite
```

### Install from Source

```bash
git clone https://github.com/zackees/pyghidra-lite
cd pyghidra-lite
uv pip install -e .
```

## Usage

### Command Line

```bash
# Start MCP server with stdio transport (default)
pyghidra-lite --allow-any-path

# Start with SSE transport (for shared server)
pyghidra-lite --transport sse --port 8000

# Pre-load binaries
pyghidra-lite --allow-any-path /path/to/binary1 /path/to/binary2

# Specify analysis profile
pyghidra-lite --profile deep --allow-any-path
```

### MCP Configuration

#### Claude Desktop

Add to `~/.config/claude/config.json`:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["--allow-any-path"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra"
      }
    }
  }
}
```

#### OpenAI Desktop / ChatGPT

Add to your MCP configuration file:

```json
{
  "servers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["--allow-any-path"]
    }
  }
}
```

Note: `stdio` transport is inferred automatically from the `command` field.

### Security Configuration

#### Path Restrictions

```bash
# Allow specific paths only
pyghidra-lite --allow-path /home/user/projects --allow-path /opt/binaries

# Allow any path (use with caution)
pyghidra-lite --allow-any-path
```

#### Environment Variables

```bash
export PYGHIDRA_LITE_ALLOW_ANY_PATH=1
export PYGHIDRA_LITE_PROJECT_DIR=/custom/project/dir
export PYGHIDRA_LITE_DEFAULT_PROFILE=fast
```

## Available Tools

### Core Analysis
- `import_binary` - Import and analyze binaries
- `list_binaries` - List loaded binaries with capabilities
- `list_functions` - List functions (compact mode available)
- `decompile` - Decompile functions to C code
- `batch_decompile` - Decompile multiple functions efficiently
- `disassemble` - Get assembly instructions
- `get_function_info` - Detailed function metadata

### Search & Discovery
- `search_strings` - Find string references (now with 500-char truncation)
- `search_symbols` - Search symbols by name
- `list_imports` - List imports with capability tags (crypto, network, file)
- `list_exports` - List exported symbols
- `get_xrefs` - Get cross-references to targets
- `get_callees` - Get functions called by a function
- `call_graph` - Get call graph with configurable depth

### Memory & Data
- `read_bytes` - Read raw bytes at addresses
- `read_string` - Read null-terminated strings
- `memory_map` - Get memory layout with permissions

### Format-Specific Tools

**ELF (Linux binaries)**
- `elf_info`, `elf_sections`, `elf_symbols`, `elf_got_plt`

**Mach-O (iOS/macOS binaries)**
- `macho_info`, `macho_segments`, `macho_dylibs`

**Swift**
- `swift_functions`, `swift_types`, `swift_decompile`, `demangle`

**Objective-C**
- `objc_classes`, `objc_methods`, `objc_decompile`

**Hermes (React Native)**
- `hermes_info`, `hermes_components`, `hermes_endpoints`

### Project Management
- `delete_binary` - Remove binary from project
- `reanalyze` - Re-run analysis with different profile

## Token Optimization Features

pyghidra-lite includes aggressive token optimization to minimize API costs:

### Opt-In Tool Lists
- `list_binaries(list_tools=False)` - Saves 500-1000 tokens per call
- `reanalyze(list_tools=False)` - Saves 200-400 tokens per call
- `import_binary(list_tools=False)` - Saves 200-400 tokens per call

### Compact Modes
- `list_functions(compact=True)` - Returns only name/address (default)
- `list_exports(compact=True)` - Returns only names (default)
- `elf_symbols(compact=True)` - Returns only name/address (default)

### Metadata Control
- `include_metadata=False` - Skips expensive ref counting (default)
- `include_provenance=False` - Omits analysis metadata (default)
- String truncation at 500 chars - Prevents token bombs from long strings

**Total Savings**: 2,000-10,000+ tokens per session

## Analysis Profiles

- **fast**: Quick triage, minimal decompiler analysis
- **default**: Balanced decompilation without full analysis
- **deep**: Thorough analysis for obfuscated code

## Multi-Agent Support

pyghidra-lite supports multiple concurrent agents through:
- **Per-binary projects**: Each binary gets isolated Ghidra project
- **Lazy loading**: Projects loaded on-demand (not at startup)
- **Session isolation**: stdio transport uses unique session IDs

## Performance Characteristics

- **CPU idle**: ~0% when not processing (optimized from 100% constant)
- **Memory**: ~300MB for new instances, 4GB for long-running with large binaries
- **Cache**: 5-minute TTL for function lists with O(1) name lookup
- **Decompilation**: Streaming with configurable timeouts

## Troubleshooting

### "No transaction is open" Error
Fixed in latest version. Ensure you're using pyghidra-lite >= 0.1.0

### High CPU Usage
This is cumulative CPU time. Check instantaneous CPU with `top -b -n 1 -p <pid>`

### Lock Errors
Per-binary projects prevent locks. If you see locks, another process is using that binary.

## Development

### Running Tests

```bash
pytest tests/
```

### Code Quality

```bash
ruff check src/
ruff format src/
```

## References

- [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25)
- [MCP GitHub](https://github.com/modelcontextprotocol)
- [OpenAI MCP Docs](https://developers.openai.com/apps-sdk/concepts/mcp-server/)
- [PyGhidra](https://github.com/dod-cyber-crime-center/pyghidra)
- [Ghidra](https://ghidra-sre.org/)

## License

MIT License - See LICENSE file

## Authors

- Zack Freedman

## Contributing

Issues and pull requests welcome at https://github.com/zackees/pyghidra-lite

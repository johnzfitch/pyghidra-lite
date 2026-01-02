# pyghidra-lite

Lightweight MCP server for Ghidra-based reverse engineering with optimized context cost and extended platform support.

## Features

### Core (optimized from pyghidra-mcp)
- Decompile functions to pseudo-C
- Symbol/function search
- Semantic code search (vector similarity)
- Import/export listing
- Cross-reference analysis
- String search
- Raw memory reading

### iOS / Mach-O
- Segment and section listing
- Objective-C class/method extraction
- Swift type demangling
- Entitlements extraction
- Info.plist parsing

### Linux / ELF
- Section analysis
- Shared library dependencies
- AppImage extraction and analysis

### Analysis Tools
- Entropy analysis (find encrypted/packed regions)
- Vulnerability pattern detection
- String cross-reference mapping
- Function comparison/diffing

### Game Files (planned)
- Unity AssetBundle parsing
- Unreal Engine .pak extraction

## Installation

```bash
# Basic install
pipx install git+https://github.com/YOUR_USER/pyghidra-lite

# With iOS support (lief)
pipx install "git+https://github.com/YOUR_USER/pyghidra-lite[ios]"

# Full install (lief + capstone + unicorn)
pipx install "git+https://github.com/YOUR_USER/pyghidra-lite[full]"
```

## Usage

### As MCP Server

Add to `~/.claude/.mcp.json`:
```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### CLI

```bash
pyghidra-lite --help
pyghidra-lite /path/to/binary
```

## Context Optimization

This fork reduces token usage by ~40% compared to pyghidra-mcp:

| Optimization | Tokens Saved |
|--------------|--------------|
| Trimmed tool descriptions | 100-150 |
| Removed wrapper classes | 30-40 |
| Simplified field schemas | 50-80 |
| **Total** | **~200-300** |

## Tool Reference

### Core Tools
| Tool | Description |
|------|-------------|
| `decompile` | Decompile function to pseudo-C |
| `list_binaries` | List project binaries |
| `get_metadata` | Get binary metadata |
| `search_symbols` | Search symbols by name |
| `search_code` | Semantic code search |
| `list_exports` | List exports |
| `list_imports` | List imports |
| `get_xrefs` | Get cross-references |
| `search_strings` | Search strings |
| `read_bytes` | Read raw memory |

### iOS Tools
| Tool | Description |
|------|-------------|
| `macho_segments` | List Mach-O segments |
| `macho_sections` | List Mach-O sections |
| `objc_classes` | List Objective-C classes |
| `objc_methods` | List class methods |
| `objc_selectors` | Search selectors |
| `swift_types` | List Swift types |
| `ios_entitlements` | Extract entitlements |
| `ios_info_plist` | Parse Info.plist |

### Linux Tools
| Tool | Description |
|------|-------------|
| `elf_sections` | List ELF sections |
| `elf_dependencies` | List shared libs |
| `appimage_info` | AppImage metadata |

### Analysis Tools
| Tool | Description |
|------|-------------|
| `analyze_entropy` | Find encrypted regions |
| `find_vuln_patterns` | Detect vulnerabilities |
| `string_xrefs` | Strings with references |
| `list_functions` | List all functions |
| `compare_functions` | Diff two functions |

## License

MIT

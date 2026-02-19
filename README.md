# pyghidra-lite

[![PyPI](https://img.shields.io/pypi/v/pyghidra-lite)](https://pypi.org/project/pyghidra-lite/)
[![Python](https://img.shields.io/pypi/pyversions/pyghidra-lite)](https://pypi.org/project/pyghidra-lite/)
[![License](https://img.shields.io/github/license/johnzfitch/pyghidra-lite)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--11--25-blue)](https://modelcontextprotocol.io)

<!-- mcp-name: io.github.johnzfitch/pyghidra-lite -->

Token-efficient MCP server for Ghidra-based reverse engineering. Analyze ELF, Mach-O, and PE binaries with Swift, Objective-C, and Hermes support.

## Quick Start

**1. Prerequisites**

JDK 21+ and Ghidra 11.x are required.

```bash
# macOS
brew install openjdk@21
brew install --cask ghidra

# Ubuntu/Debian
sudo apt install openjdk-21-jdk
# Download Ghidra from https://ghidra-sre.org

# Arch Linux
sudo pacman -S jdk21-openjdk
yay -S ghidra
```

Ghidra at `/opt/ghidra` or `~/ghidra` is found automatically. Set `GHIDRA_INSTALL_DIR` only for non-standard paths.

**2. Install pyghidra-lite**

```bash
pip install pyghidra-lite
```

**3. Add to Claude Code**

Create `.mcp.json` in your project (or `~/.claude.json` for global):

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["serve", "--allow-path", "/path/to/binaries"]
    }
  }
}
```

**4. Use it**

```
You: Analyze the binary at /path/to/binaries/app

Claude: [calls import_binary, list_functions, decompile...]
```

## Installation

### PyPI (recommended)

```bash
pip install pyghidra-lite
```

### Arch Linux (AUR)

```bash
yay -S python-pyghidra-lite
```

### From source

```bash
git clone https://github.com/johnzfitch/pyghidra-lite
cd pyghidra-lite
pip install -e .
```

## MCP Configuration

### Basic (allow specific paths)

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["serve", "--allow-path", "/home/user/binaries"]
    }
  }
}
```

### With explicit Ghidra path

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": [
        "serve",
        "--ghidra-dir", "/path/to/ghidra",
        "--allow-path", "/home/user/binaries"
      ]
    }
  }
}
```

### Multiple paths

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": [
        "serve",
        "--allow-path", "/home/user/binaries",
        "--allow-path", "/opt/targets"
      ]
    }
  }
}
```

### Allow any path (development only)

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["serve", "--allow-any-path"]
    }
  }
}
```

## Tools

### Core (3)
| Tool | Description |
|------|-------------|
| `import_binary` | Import binary with async progress reporting |
| `delete_binary` | Remove from project |
| `reanalyze` | Re-run with different profile |

### Discovery (4)
| Tool | Description |
|------|-------------|
| `list_binaries` | List loaded binaries |
| `list_functions` | Functions with metadata (compact by default) |
| `list_imports` | Imports with capability tags |
| `list_exports` | Exported symbols |

### Analysis (8)
| Tool | Description |
|------|-------------|
| `get_function_info` | Function metadata and callers/callees |
| `disassemble` | Assembly for a function |
| `decompile` | Pseudo-C with callees and strings |
| `batch_decompile` | Decompile multiple functions |
| `get_xrefs` | Cross-references |
| `get_callees` | What a function calls |
| `call_graph` | Call graph with configurable depth |
| `memory_map` | Memory layout with permissions |

### Search (2)
| Tool | Description |
|------|-------------|
| `search_strings` | Strings with xrefs |
| `search_symbols` | Symbol name search |

### Data (2)
| Tool | Description |
|------|-------------|
| `read_bytes` | Raw memory |
| `read_string` | Null-terminated string |

### ELF (4)
| Tool | Description |
|------|-------------|
| `elf_info` | ELF structure summary |
| `elf_sections` | ELF sections |
| `elf_symbols` | ELF symbols |
| `elf_got_plt` | GOT/PLT entries |

### Mach-O (3)
| Tool | Description |
|------|-------------|
| `macho_info` | Mach-O structure summary |
| `macho_segments` | Segments and sections |
| `macho_dylibs` | Linked dylibs |

### Swift (4)
| Tool | Description |
|------|-------------|
| `swift_functions` | Swift functions (demangled) |
| `swift_types` | Swift types from metadata |
| `swift_decompile` | Decompile with demangled names |
| `demangle` | Swift symbol demangling |

### Objective-C (3)
| Tool | Description |
|------|-------------|
| `objc_classes` | Objective-C classes |
| `objc_methods` | Objective-C methods |
| `objc_decompile` | Method decompile |

### Hermes (3)
| Tool | Description |
|------|-------------|
| `hermes_info` | Hermes bundle summary |
| `hermes_components` | React component names |
| `hermes_endpoints` | API endpoints/URLs |

## Analysis Profiles

| Profile | Use Case |
|---------|----------|
| `fast` | Quick triage, disables 20 slow analyzers (default) |
| `default` | Balanced, full Ghidra analysis |
| `deep` | Thorough analysis for obfuscated code |

The server defaults to `fast` to stay within MCP timeout limits. Use `reanalyze` to run deeper analysis when needed:

```python
# Default import uses fast profile
import_binary("/path/to/binary")

# Re-analyze with deep profile when you need more detail
reanalyze("binary-name", profile="deep")
```

## Token Efficiency

pyghidra-lite is designed for minimal token usage:

- **Compact output by default** - `list_functions` returns minimal fields
- **Opt-in verbosity** - pass `compact=false` for full metadata
- **Progress reporting** - large imports report progress every 10% or 60s
- **Truncated strings** - long strings capped at 500 chars

## Multi-Agent Support

Each binary gets its own Ghidra project, enabling:

- Parallel analysis of different binaries
- Shared results across agents
- Persistent analysis (survives restarts)
- Content-addressed storage (same binary = same analysis)

Projects stored in `~/.local/share/pyghidra-lite/projects/`.

## Links

- [PyPI Package](https://pypi.org/project/pyghidra-lite/)
- [AUR Package](https://aur.archlinux.org/packages/python-pyghidra-lite)
- [MCP Registry](https://registry.modelcontextprotocol.io)
- [Issue Tracker](https://github.com/johnzfitch/pyghidra-lite/issues)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT

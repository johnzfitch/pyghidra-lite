# pyghidra-lite

Lightweight MCP server for Ghidra-based reverse engineering. Focused toolset with smart backend features.

## Design Philosophy

1. **Small tool surface**: 17 focused tools that agents actually use
2. **Rich metadata**: Functions include `refs_in`, `refs_out`, `has_strings`, `is_library` for prioritization
3. **Stable IDs**: Content-addressed `unit_id` and `stable_id` survive renames
4. **Analysis profiles**: `fast`/`default`/`deep` tradeoff without changing tools
5. **Container support**: APK/IPA/AppImage auto-extraction
6. **Central project**: All binaries in `~/.local/share/pyghidra-lite/projects` (not per-cwd)

## Requirements

- Ghidra 11.x installed
- `GHIDRA_INSTALL_DIR` environment variable set to Ghidra installation path
- Python 3.11+

## Installation

```bash
cd pyghidra-lite
uv pip install -e .
```

## Usage

### As MCP Server (Claude Code)

Add to `~/.claude/.mcp.json`:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/pyghidra-lite", "pyghidra-lite", "--transport", "stdio"]
    }
  }
}
```

Or with a binary pre-loaded:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/pyghidra-lite", "pyghidra-lite", "--profile", "fast", "/path/to/binary"]
    }
  }
}
```

### Command Line

```bash
# Start server (binaries imported via MCP tools)
uv run pyghidra-lite

# Pre-load binaries with fast profile
uv run pyghidra-lite --profile fast /path/to/app.apk

# Use custom project location
uv run pyghidra-lite --project-dir /tmp/ghidra-projects --project-name myproject
```

## Tools

### Import (3)
| Tool | Description |
|------|-------------|
| `import_binary` | Import binary or container with profile selection |
| `delete_binary` | Remove from project |
| `reanalyze` | Re-run with different profile |

### Discovery (6)
| Tool | Description |
|------|-------------|
| `list_binaries` | List all binaries with status |
| `get_info` | Binary metadata (arch, format, counts) |
| `get_status` | Analysis progress |
| `list_functions` | Functions with metadata (sortable by refs) |
| `list_imports` | Imports with capability tags |
| `list_exports` | Exported symbols |

### Analysis (3)
| Tool | Description |
|------|-------------|
| `decompile` | Pseudo-C with callees and strings |
| `get_xrefs` | Who calls/uses this |
| `get_callees` | What this function calls |

### Search (3)
| Tool | Description |
|------|-------------|
| `search_functions` | Function name search |
| `search_strings` | Strings with xrefs |
| `search_symbols` | Symbol name search |

### Data (2)
| Tool | Description |
|------|-------------|
| `read_bytes` | Raw memory |
| `read_string` | Null-terminated string |

## Analysis Profiles

| Profile | Use Case |
|---------|----------|
| `fast` | Quick triage, minimal decompiler analysis |
| `default` | Balanced analysis |
| `deep` | Full analysis for obfuscated code |

```python
# Import with fast profile for triage
import_binary("/path/to/app.apk", profile="fast")

# Re-analyze specific binary with deep profile
reanalyze("libnative.so", profile="deep")
```

## Container Support

```python
# APK auto-extracts to multiple units
import_binary("/path/to/app.apk")
# Returns: ContainerInfo with units=[libfoo.so, libbar.so, classes.dex, ...]

# IPA extracts main binary + frameworks
import_binary("/path/to/App.ipa")
```

## Function Metadata

`list_functions` returns prioritization hints:

```python
FunctionInfo(
    name="decrypt_data",
    address="0x1234",
    stable_id="a1b2c3...",     # Survives renames
    size=256,
    refs_in=47,                 # Many callers = important
    refs_out=3,                 # Few callees = leaf function
    has_strings=True,           # References literals
    is_library=False,           # Not known stdlib
    is_thunk=False,             # Not a wrapper
)
```

Sort by `refs_in` to find important functions, `refs_out` to find orchestrators.

## Import Capability Tags

`list_imports` tags imports with capabilities:

```python
ImportInfo(
    name="SSL_read",
    library="libssl.so",
    tags=["crypto", "network"],  # Auto-detected
)
```

Tags: `crypto`, `network`, `file`, `process`, `memory`, `jni`

## Provenance

All results include provenance for reproducibility:

```python
Provenance(
    unit_id="abc123...",
    profile=AnalysisProfile.DEFAULT,
    ghidra_version="11.4.3",
    tool_version="0.1.0",
)
```

## Project Structure

Unlike pyghidra-mcp which creates projects per working directory, pyghidra-lite uses a central location:

```
~/.local/share/pyghidra-lite/
└── projects/
    └── pyghidra_lite/
        ├── pyghidra_lite.gpr
        └── pyghidra_lite.rep/
```

This means:
- Binaries are shared across sessions
- No more scattered `pyghidra_mcp_projects/` directories
- Persistent analysis results

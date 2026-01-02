# pyghidra-lite

Lightweight MCP server for Ghidra-based reverse engineering. Focused toolset with smart backend features.

## Design Philosophy

1. **Small tool surface**: 17 focused tools that agents actually use
2. **Rich metadata**: Functions include `refs_in`, `refs_out`, `has_strings`, `is_library` for prioritization
3. **Stable IDs**: Content-addressed `unit_id` and `stable_id` survive renames
4. **Analysis profiles**: `fast`/`default`/`deep` tradeoff without changing tools
5. **Container support**: APK/IPA/AppImage auto-extraction

## Tools

### Import
| Tool | Description |
|------|-------------|
| `import_binary` | Import binary or container with profile selection |
| `delete_binary` | Remove from project |
| `reanalyze` | Re-run with different profile |

### Discovery
| Tool | Description |
|------|-------------|
| `list_binaries` | List all binaries with status |
| `get_info` | Binary metadata (arch, format, counts) |
| `get_status` | Analysis progress |
| `list_functions` | Functions with metadata (sortable by refs) |
| `list_imports` | Imports with capability tags |
| `list_exports` | Exported symbols |

### Analysis
| Tool | Description |
|------|-------------|
| `decompile` | Pseudo-C with callees and strings |
| `get_xrefs` | Who calls/uses this |
| `get_callees` | What this function calls |

### Search
| Tool | Description |
|------|-------------|
| `search_functions` | Semantic code search |
| `search_strings` | Strings with xrefs |
| `search_symbols` | Symbol name search |

### Data
| Tool | Description |
|------|-------------|
| `read_bytes` | Raw memory |
| `read_string` | Null-terminated string |

## Analysis Profiles

| Profile | Use Case |
|---------|----------|
| `fast` | Quick triage, minimal decompiler |
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

# AppImage extracts embedded ELFs
import_binary("/path/to/App.AppImage")
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

## Provenance

All results include provenance for reproducibility:

```python
Provenance(
    unit_id="abc123...",
    profile=AnalysisProfile.DEFAULT,
    ghidra_version="11.0",
    tool_version="0.1.0",
)
```

## Installation

```bash
# From source
cd pyghidra-lite
pip install -e .

# Run server
pyghidra-lite --profile default /path/to/binary
```

## MCP Configuration

Add to `~/.claude/.mcp.json`:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["--transport", "stdio", "--profile", "default"]
    }
  }
}
```

## Credits

Architecture insights from ChatGPT's scaffold document. Context optimization learnings from pyghidra-mcp.

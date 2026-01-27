# pyghidra-lite

Lightweight MCP server for Ghidra-based reverse engineering. Focused toolset with smart backend features.

## Design Philosophy

1. **Focused tool surface**: Core tools plus capability-specific extensions
2. **Rich metadata**: Functions include `refs_in`, `refs_out`, `has_strings`, `is_library` for prioritization
3. **Stable IDs**: Content-addressed `unit_id` and `stable_id` survive renames
4. **Analysis profiles**: `fast`/`default`/`deep` tradeoff without changing tools
5. **Container detection**: APK/IPA/AppImage detection hooks (extraction TODO)
6. **Per-binary projects**: Each binary gets its own Ghidra project for multi-agent parallelism
7. **Persistent analysis**: Shared cache persists across agent suspend/resume cycles

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

**Out of the box (stdio transport, automatic session isolation):**

Add to `~/.claude/mcp_config.json`:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["--allow-any-path"]
    }
  }
}
```

Each agent automatically gets its own isolated session. No conflicts, no manual setup required!

**With path restrictions (recommended for production):**

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": [
        "--allow-path", "/home/user/binaries",
        "--allow-path", "/opt/apps"
      ]
    }
  }
}
```

**With development installation:**

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/pyghidra-lite",
        "pyghidra-lite",
        "--allow-any-path"
      ]
    }
  }
}
```

### Command Line

```bash
# Start server (binaries imported via MCP tools)
uv run pyghidra-lite --allow-path /path/to/binaries

# Pre-load binaries with fast profile
uv run pyghidra-lite --profile fast --allow-path /path/to/binaries /path/to/app.apk

# Use custom project location
uv run pyghidra-lite --project-dir /tmp/ghidra-projects --project-name myproject --allow-path /path/to/binaries
```

### Multi-Agent Usage

pyghidra-lite works out of the box with multiple agents using **per-binary projects**:

```
~/.local/share/pyghidra-lite/
└── projects/
    ├── abc123def456/    # Binary 1's project
    │   ├── abc123def456.gpr
    │   └── abc123def456.rep/
    └── 789ghi012jkl/    # Binary 2's project
        ├── 789ghi012jkl.gpr
        └── 789ghi012jkl.rep/
```

**Benefits:**
- ✅ **No configuration needed** - just add to MCP config
- ✅ **Persistent analysis** - work survives agent suspend/resume
- ✅ **Shared cache** - all agents share analysis results
- ✅ **Parallel analysis** - different binaries analyzed simultaneously
- ✅ **Minimal disk usage** - each binary analyzed once, shared by all
- ⚠️ **Same-binary locking** - only locks when 2+ agents work on identical binary

**When locks occur:**
- Two agents analyzing the exact same binary (same content hash) simultaneously
- **Does NOT lock** when agents work on different binaries
- Rare in practice - agents typically work on different files or at different times

**SSE Transport (Optional):**

SSE transport is available but not required. Both stdio and SSE use the same shared project structure:

```bash
# Optional: Start SSE server for reduced process overhead
pyghidra-lite --transport sse --port 8001 --allow-any-path
```

SSE benefits: Single server process instead of one per agent, slightly less memory usage.

## Import Policy (Multi-client)

`import_binary` is allowlisted by default for multi-client safety.

- Allow specific roots: `--allow-path /path/to/binaries` (repeatable) or `PYGHIDRA_LITE_ALLOWED_PATHS` (pathsep-separated).
- Allow any path (unsafe): `--allow-any-path` or `PYGHIDRA_LITE_ALLOW_ANY_PATH=1`.

## Tools

Token-efficient defaults: `list_functions`, `list_exports`, `swift_functions`, and `elf_symbols` return compact output by default.
Pass `compact=false` to request full metadata.

### Import (3)
| Tool | Description |
|------|-------------|
| `import_binary` | Import binary or container with profile selection |
| `delete_binary` | Remove from project |
| `reanalyze` | Re-run with different profile |

### Discovery (4)
| Tool | Description |
|------|-------------|
| `list_binaries` | List all binaries with status |
| `list_functions` | Functions with metadata (sortable by refs) |
| `list_imports` | Imports with capability tags |
| `list_exports` | Exported symbols |

### Analysis (5)
| Tool | Description |
|------|-------------|
| `get_function_info` | Function metadata and callers/callees |
| `disassemble` | Assembly for a function |
| `decompile` | Pseudo-C with callees and strings |
| `get_xrefs` | Who calls/uses this |
| `get_callees` | What this function calls |

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
| `swift_decompile` | Swift decompile with demangled callees |
| `demangle` | Swift symbol demangling |

### Objective-C (3)
| Tool | Description |
|------|-------------|
| `objc_classes` | Objective-C classes |
| `objc_methods` | Objective-C methods |
| `objc_decompile` | Objective-C method decompile |

### Hermes (3)
| Tool | Description |
|------|-------------|
| `hermes_info` | Hermes bundle summary |
| `hermes_components` | React component names |
| `hermes_endpoints` | API endpoints/URLs |

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

## Container Detection

Container extraction is not yet implemented. `import_binary` currently expects a direct
binary path; container detection helpers are in place for future extraction work.

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

All agents share a common per-binary project structure:

```
~/.local/share/pyghidra-lite/
└── projects/
    ├── abc123def456/              # Binary 1 (unit_id = SHA256 hash)
    │   ├── abc123def456.gpr       # Ghidra project file
    │   └── abc123def456.rep/      # Analysis repository
    └── 789ghi012jkl/              # Binary 2 (unit_id)
        ├── 789ghi012jkl.gpr
        └── 789ghi012jkl.rep/
```

**Key features:**
- **Content-addressed**: Binary identified by SHA256 hash of contents
- **Shared analysis**: All agents see the same analysis results
- **Persistent**: Analysis survives agent restarts and suspend/resume
- **Per-binary locking**: Each binary has independent lock
- **No duplication**: Same binary analyzed once, shared by all

**When is analysis reused?**
- Same binary file (identical content) → always reuses existing analysis
- Different binary → gets its own project, analyzes independently
- Binary modified → new hash, new analysis (old analysis preserved)

**Cleanup:**

To remove old analysis:

```bash
# Remove all analyzed binaries
rm -rf ~/.local/share/pyghidra-lite/projects

# Remove specific binary (find by partial hash)
rm -rf ~/.local/share/pyghidra-lite/projects/abc123*
```

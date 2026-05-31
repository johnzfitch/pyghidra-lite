# pyghidra-lite

Token-efficient MCP server for Ghidra-based reverse engineering.

## Architecture

- `src/pyghidra_lite/server.py` - MCP server, CLI, tool registration
- `src/pyghidra_lite/backend.py` - JVM/Ghidra bridge, project management
- `src/pyghidra_lite/tools.py` - Core RE tools (decompile, xrefs, etc.)
- `src/pyghidra_lite/formats.py` - ELF + Mach-O format tools
- `src/pyghidra_lite/lang.py` - Swift + ObjC language tools
- `src/pyghidra_lite/hermes.py` - React Native/Hermes tools

## Development

```bash
uv sync                    # Install deps
uv run pytest             # Run tests
uv run pyghidra-lite serve # Start MCP server
```

## Releasing

### 1. Bump version

Update version in **three** places, keeping them in sync:
- `pyproject.toml` (`version`)
- `server.json` (top-level `version` **and** the `packages[].version`)
- `src/pyghidra_lite/__init__.py` (`__version__`, exposed by `pyghidra-lite --version`)

### 2. PyPI

Create a GitHub release (e.g., `v0.5.0`). The `publish.yml` workflow handles PyPI upload via trusted publishing.

### 3. MCP Registry

The MCP registry requires manual publish (OIDC workflow needs org-level permissions).

```bash
# First time: download the publisher
gh release download --repo modelcontextprotocol/registry --pattern 'mcp-publisher_linux_amd64.tar.gz'
tar -xzf mcp-publisher_linux_amd64.tar.gz -C .tools/
rm mcp-publisher_linux_amd64.tar.gz

# Login (opens browser for GitHub OAuth)
.tools/mcp-publisher login github

# Publish (reads server.json)
.tools/mcp-publisher publish
```

The CLI caches auth in `.mcpregistry_*` (gitignored). Subsequent publishes only need the `publish` command.

Registry listing: https://registry.modelcontextprotocol.io/?q=pyghidra-lite

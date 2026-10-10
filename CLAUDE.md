# pyghidra-lite

Token-efficient MCP server for Ghidra-based reverse engineering.

## Architecture

- `src/pyghidra_lite/server.py` - MCP server, CLI, tool registration
- `src/pyghidra_lite/backend.py` - JVM/Ghidra bridge, project management
- `src/pyghidra_lite/tools.py` - Core RE tools (decompile, xrefs, etc.)
- `src/pyghidra_lite/formats.py` - ELF + Mach-O format tools
- `src/pyghidra_lite/lang.py` - Swift + ObjC language tools
- `src/pyghidra_lite/hermes.py` - React Native/Hermes tools
- `src/pyghidra_lite/doctor.py` - `pyghidra-lite doctor` environment checks
- `plugins/pyghidra-lite/` - Claude Code plugin (MCP config + reverse-engineering skill); marketplace in `.claude-plugin/marketplace.json`

## Development

```bash
uv sync                    # Install deps
uv run pytest             # Run tests
uv run pyghidra-lite serve # Start MCP server
```

## Releasing

### 1. Bump version

Update version in **five** places, keeping them in sync (`tests/test_plugin.py` fails otherwise):
- `pyproject.toml` (`version`)
- `server.json` (top-level `version` **and** the `packages[].version`)
- `src/pyghidra_lite/__init__.py` (`__version__`, exposed by `pyghidra-lite --version`)
- `plugins/pyghidra-lite/.claude-plugin/plugin.json` (`version`)
- `plugins/pyghidra-lite/.mcp.json` (the `pyghidra-lite==<version>` pin in `args`)

The publish workflow builds the release tag's commit (or the dispatched branch), so
merge the version bump to master first, then create the release right away: until the
new version is on PyPI, the plugin's `uvx` pin can't install it. PyPI versions are
immutable -- a version number can be uploaded only once.

### 2. PyPI

Create a GitHub release (e.g., `v0.5.0`). The `publish.yml` workflow handles PyPI upload via trusted publishing.

### 3. MCP Registry

Automatic: `publish.yml` runs the registry job (`mcp-registry.yml`, GitHub OIDC login) after
the PyPI job succeeds, waiting until PyPI serves the new version -- the registry rejects a
version PyPI doesn't have yet. To (re-)register an already-published version, run the
**Publish to MCP Registry** workflow manually (`gh workflow run mcp-registry.yml`, optional
`-f version=X.Y.Z`; default is the version in `server.json`), or re-run a failed job.

Manual fallback from a workstation:

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

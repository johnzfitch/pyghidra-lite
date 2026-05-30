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
      "command": "pyghidra-lite"
    }
  }
}
```

**4. Use it**

```
You: Analyze the binary at /path/to/binaries/app

Claude: [calls load, info, code...]
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

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "uvx",
      "args": ["pyghidra-lite"]
    }
  }
}
```

`uvx` auto-installs pyghidra-lite from PyPI on first run. Ghidra is auto-detected; set `GHIDRA_INSTALL_DIR` in `env` if needed:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "uvx",
      "args": ["pyghidra-lite"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra"
      }
    }
  }
}
```

### Claude Code

Create `.mcp.json` in your project (or `~/.claude.json` for global):

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite"
    }
  }
}
```

#### Direct mode (skip proxy)

For single-session use or debugging, run the server directly:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": ["serve"]
    }
  }
}
```

#### With explicit Ghidra path

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": [
        "serve",
        "--ghidra-dir", "/path/to/ghidra"
      ]
    }
  }
}
```

#### Restrict to specific paths

By default, pyghidra-lite can load binaries from any path (the MCP client handles permissions). Use `--restrict-path` to lock down access:

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite",
      "args": [
        "serve",
        "--restrict-path", "/home/user/binaries",
        "--restrict-path", "/opt/targets"
      ]
    }
  }
}
```

#### Shared HTTP transport (network access)

The HTTP/SSE transports are shared and apply DNS-rebinding protection (Host/Origin
validation). Binding to a non-loopback address additionally **requires** both
`--restrict-path` and a bearer token:

```bash
pyghidra-lite serve -t streamable-http --host 0.0.0.0 \
  --restrict-path /opt/targets \
  --auth-token "$PYGHIDRA_LITE_AUTH_TOKEN" \
  --allowed-host re.example.com:8000   # if fronted under another hostname
```

Clients then send `Authorization: Bearer <token>` on every request. Terminate TLS
at a reverse proxy for remote access.

## Tools (8)

pyghidra-lite provides 8 consolidated tools that auto-detect format (ELF/Mach-O/PE) and language (Swift/ObjC/Hermes):

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `load` | Import and analyze binary | `path`, `profile?`, `fresh?`, `bootstrap?`, `bootstrap_mode?` |
| `delete` | Remove binary and cancel jobs | `name` |
| `binaries` | List binaries + job status | `jobs?`, `rank_sources?` |
| `info` | Binary overview | `binary`, `detail?` (summary/full/format/sections/entropy) |
| `functions` | List/search functions | `binary`, `query?`, `type?` (all/swift/objc/imports/exports) |
| `code` | Decompile or disassemble | `binary`, `target`, `what?` (decompile/asm), `cfg?` |
| `xrefs` | References and call graphs | `binary`, `target`, `direction?`, `depth?`, `diff?` |
| `search` | Find strings, bytes, symbols | `binary`, `query`, `type?`, `mode?`, `bg?` |

### Examples

```python
# Import and analyze
load("/path/to/binary", profile="fast")

# Version-track from a prior build, including synthetic IDs for unnamed code
load("/path/to/new.bin", profile="deep", bootstrap="old.bin", bootstrap_mode="all")

# Get overview with full triage
info("mybinary", detail="full")

# List Swift functions
functions("mybinary", type="swift")

# Decompile with CFG
code("mybinary", "main", cfg=True)

# Search strings in background
search("mybinary", ["password", "api_key"], bg=True)

# Get cross-references
xrefs("mybinary", "malloc", depth=2)
```

### Auto-Detection

All tools automatically detect:
- **Format**: ELF, Mach-O, PE
- **Language**: Swift, Objective-C, Hermes/React Native
- **Runtime**: Bun, Node.js, Electron, PyInstaller

Use the `type` and `detail` parameters to access format/language-specific features.

### Bootstrap Modes

- `bootstrap_mode="named"`: transfer only meaningful source names (default).
- `bootstrap_mode="all"`: also assign stable synthetic labels to source `FUN_*` functions during transfer, which is useful for large version-to-version bootstrap workflows where uniqueness matters more than semantics.

## Analysis Profiles

| Profile | Use Case |
|---------|----------|
| `fast` | Quick triage, disables 20 slow analyzers (default) |
| `default` | Balanced, full Ghidra analysis |
| `deep` | Thorough analysis for obfuscated code |

The server defaults to `fast` to stay within MCP timeout limits. Use `load(fresh=True)` to run deeper analysis when needed:

```python
# Default import uses fast profile
load("/path/to/binary")

# Re-analyze with deep profile
load("/path/to/binary", profile="deep", fresh=True)
```

## Token Efficiency

pyghidra-lite is designed for minimal token usage:

- **Compact output by default** - `functions(binary, type="all")` returns minimal `{name, addr}` pairs
- **Opt-in detail** - use `info(detail="full")`, `code(cfg=True)`, or richer `type`/`what` modes only when needed
- **Progress reporting** - large imports report progress every 10% or 60s
- **Truncated strings** - long strings capped at 500 chars

## Architecture

By default, `pyghidra-lite` runs as a lightweight stdio proxy (~10MB) that forwards to a persistent shared HTTP backend (~500MB JVM). Multiple sessions share a single JVM instead of each spawning their own.

```
Claude Code session 1 ──stdio──> proxy ──┐
Claude Code session 2 ──stdio──> proxy ──┼──HTTP──> shared backend (1 JVM)
Claude Code session 3 ──stdio──> proxy ──┘        localhost:19101
```

The proxy auto-starts the backend on first use and the backend auto-exits after 30 minutes of idle. A file lock prevents concurrent proxy starts from spawning duplicate backends.

| Command | What it does |
|---------|-------------|
| `pyghidra-lite` | Stdio proxy (default) -- auto-starts backend |
| `pyghidra-lite serve` | Direct stdio server (1 JVM per session) |
| `pyghidra-lite serve -t streamable-http` | Start persistent HTTP backend manually |
| `pyghidra-lite stop` | Stop the shared backend |

Set `PYGHIDRA_LITE_NO_AUTOSTART=1` to disable auto-start (useful with systemd).

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

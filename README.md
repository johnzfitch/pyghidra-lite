# pyghidra-lite

[![PyPI][pypi-badge]][pypi]
[![Python][python-badge]][pypi]
[![Downloads][downloads-badge]][pypi]
[![License][license-badge]](LICENSE)<br>
[![CI][ci-badge]][ci]
[![MCP Registry][registry-badge]][registry]
[![MCP spec][mcp-badge]][mcp]
[![Claude Code plugin][plugin-badge]](#claude-code-plugin)
[![Ghidra][ghidra-badge]][ghidra]
[![Platforms][platform-badge]](#quick-start)

[pypi]: https://pypi.org/project/pyghidra-lite/
[pypi-badge]: https://img.shields.io/pypi/v/pyghidra-lite?logo=pypi&logoColor=white
[python-badge]: https://img.shields.io/pypi/pyversions/pyghidra-lite?logo=python&logoColor=white
[downloads-badge]: https://img.shields.io/pypi/dm/pyghidra-lite
[license-badge]: https://img.shields.io/github/license/johnzfitch/pyghidra-lite
[ci]: https://github.com/johnzfitch/pyghidra-lite/actions/workflows/ci.yml
[ci-badge]: https://img.shields.io/github/actions/workflow/status/johnzfitch/pyghidra-lite/ci.yml?branch=master&label=CI&logo=githubactions&logoColor=white
[registry]: https://registry.modelcontextprotocol.io/?q=pyghidra-lite
[registry-badge]: https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fregistry.modelcontextprotocol.io%2Fv0%2Fservers%2Fio.github.johnzfitch%252Fpyghidra-lite%2Fversions%2Flatest&query=%24.server.version&label=MCP%20Registry&prefix=v&color=blue
[mcp]: https://modelcontextprotocol.io/specification/2025-11-25
[mcp-badge]: https://img.shields.io/badge/MCP_spec-2025--11--25-blue
[plugin-badge]: https://img.shields.io/badge/Claude_Code-plugin-D97757?logo=claude&logoColor=white
[ghidra]: https://github.com/NationalSecurityAgency/ghidra/releases
[ghidra-badge]: https://img.shields.io/badge/Ghidra-11.x_%7C_12.x-E21E2B
[platform-badge]: https://img.shields.io/badge/platform-Linux_%7C_macOS_%7C_Windows-lightgrey

<!-- mcp-name: io.github.johnzfitch/pyghidra-lite -->

Token-efficient MCP server for Ghidra-based reverse engineering. Analyze ELF, Mach-O, and PE binaries with Swift, Objective-C, and Hermes support &mdash; decompile, disassemble, trace calls and **value flow**, recover **data types**, and map addresses back to **file offsets**. Runs on Linux, macOS, and Windows; ships as a Claude Code plugin with a bundled reverse-engineering skill.

**Bottom line:** a lean, security-first Ghidra MCP. It is **read-only by default** — analysis tools never mutate your binaries or the server's configuration (which is frozen for the life of the process). The one tool that writes, `annotate` (rename / comment / prototype), is **opt-in** (`--allow-write`) and **human-confirmed**: every change is approved by you through an MCP elicitation prompt before it's committed, and it fails closed if your client can't ask. You get an analyst-agent that can persist its findings — under supervision — without giving up the read-only safety story.

## Quick Start

**1. Prerequisites**

A 64-bit JDK 21+ and Ghidra 11.x or 12.x are required (tested with Ghidra 12.1.2 and JDK 21).

```bash
# macOS
brew install openjdk@21
brew install ghidra

# Ubuntu/Debian
sudo apt install openjdk-21-jdk
# Download Ghidra from https://ghidra-sre.org

# Arch Linux
sudo pacman -S jdk21-openjdk
yay -S ghidra
```

Ghidra installed via Homebrew (`brew install ghidra`) or to `/opt/ghidra` or `~/ghidra` is found automatically. Elsewhere &mdash; including any Windows install &mdash; point `GHIDRA_INSTALL_DIR` at the extracted `ghidra_<version>_PUBLIC` folder.

**2. Install** &mdash; pick one

<dl>
  <dt>Claude Code plugin (recommended for Claude Code)</dt>
  <dd>MCP server + reverse-engineering skill in one step; prompts for your Ghidra directory. Needs <a href="https://docs.astral.sh/uv/">uv</a> on <code>PATH</code>.</dd>
</dl>

```
/plugin install pyghidra-lite --marketplace johnzfitch/pyghidra-lite
```

<dl>
  <dt>Any MCP client</dt>
  <dd>Install the package, then add it to your client (Claude Code: <code>.mcp.json</code> in your project or <code>~/.claude.json</code>; other clients: see <a href="#mcp-configuration">MCP Configuration</a>).</dd>
</dl>

```bash
pip install pyghidra-lite
```

```json
{
  "mcpServers": {
    "pyghidra-lite": {
      "command": "pyghidra-lite"
    }
  }
}
```

**3. Check the environment**

```bash
pyghidra-lite doctor   # Ghidra, JDK, decompiler, project dir, locks; exits 1 on problems
```

> [!TIP]
> Plugin users without a shell install can run the same check with `uvx pyghidra-lite doctor`.

**4. Use it**

```
You: Analyze the binary at /path/to/binaries/app

Claude: [calls load, info, code...]
```

## Installation

### Claude Code plugin

Installs the MCP server (run with `uvx`, so [uv](https://docs.astral.sh/uv/) must be on
`PATH`) together with the `pyghidra-lite:reverse-engineering` workflow skill, and asks
for your Ghidra directory, cache directory, optional path restriction and whether to
allow `annotate`:

```
/plugin install pyghidra-lite --marketplace johnzfitch/pyghidra-lite
```

- On Claude Code before 2.1.275, run `/plugin marketplace add johnzfitch/pyghidra-lite`
  first, then `/plugin install pyghidra-lite@pyghidra-lite`.
- The plugin pins an exact package version and runs one server per session. After a
  plugin update, run `/reload-plugins` (or start a new session) to switch to it.
- Change the settings later under `/config`.

> [!WARNING]
> If you also have a manual `pyghidra-lite` entry in `.mcp.json` or `~/.claude.json`,
> remove it &mdash; otherwise every tool appears twice.

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

## Tools (9)

pyghidra-lite provides 8 read-only analysis tools plus 1 opt-in write tool, all
auto-detecting format (ELF/Mach-O/PE) and language (Swift/ObjC/Hermes):

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `load` | Import and analyze binary | `path`, `profile?`, `fresh?`, `bootstrap?`, `bootstrap_mode?` |
| `delete` | Remove binary and cancel jobs | `name` |
| `binaries` | List binaries + job status | `jobs?`, `rank_sources?` |
| `info` | Binary overview | `binary`, `detail?` (summary/full/format/sections/entropy) |
| `functions` | List/search functions, imports, exports | `binary`, `query?`, `type?` (all/swift/objc/imports/exports/types/got/dylibs), `limit?` |
| `code` | Decompile, disassemble, p-code, bytes | `binary`, `target`, `what?` (decompile/asm/pcode/bytes/string), `cfg?` |
| `xrefs` | References and call graphs | `binary`, `target`, `direction?`, `depth?`, `diff?` |
| `search` | Find strings, bytes, symbols, data types | `binary`, `query`, `type?` (strings/symbols/bytes/all/blob/extract/types), `mode?`, `bg?` |
| `annotate` 🔒 | Rename / comment / set prototype | `binary`, `target`, `action`, `name?`/`comment?`/`prototype?` |

🔒 `annotate` is the only tool that writes. It is disabled unless the server is
started with `--allow-write`, and every change requires interactive
confirmation (MCP elicitation) before it is committed — clients that can't
confirm get a preview only. See [Writing back](#writing-back).

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

# Value flow: SSA p-code, grouped by basic block; each value is defined once
code("mybinary", "parse_header", what="pcode")
# ...or just where one argument's value goes (forward slice; ~10x smaller on real code)
code("mybinary", "parse_header,param_2", what="pcode")

# Raw bytes plus where they live in the file (for patching)
code("mybinary", "0x4011a0,64", what="bytes")   # -> hex, ascii, file_offset, block

# Recovered struct layouts / enums / typedefs
search("mybinary", "sockaddr", type="types")
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

## Writing back

By default pyghidra-lite is **read-only** — no tool mutates your binaries. To let
an agent persist findings (rename a function, attach a comment, fix a prototype),
start the server with `--allow-write`:

```bash
pyghidra-lite serve --allow-write          # or PYGHIDRA_LITE_ALLOW_WRITE=1
```

Then the `annotate` tool becomes usable:

```python
annotate("mybinary", target="FUN_00401000", action="rename", name="parse_header")
annotate("mybinary", target="parse_header", action="comment", comment="validates the v2 header")
annotate("mybinary", target="parse_header", action="prototype", prototype="int parse_header(char *buf, int len)")
```

Every call is **human-confirmed**: the server sends an MCP elicitation prompt
showing the exact `old -> new` change, and only commits if you accept. If the
server was started without `--allow-write`, the tool refuses; if your MCP client
doesn't support elicitation, the tool returns a preview with `applied: false`
and writes nothing (fail closed). Confirmed changes are written in a single
Ghidra transaction and saved to the on-disk project.

**Audit journal.** Because MCP elicitation ultimately trusts the client (an
autonomous "auto-approve" client *can* self-confirm), every write is recorded in
`annotate_audit.jsonl` next to the projects — and every declined or failed
attempt is logged too. Each line records `old -> new`, so the journal is both an
accountability trail and an undo log; a flood of entries is your signal that an
auto-agent is churning, and the server also nudges (`ctx.warning`) as write
volume climbs. The journal is **fail-closed and hardened**: a write is recorded
*before* it's applied (if it can't be journaled, it isn't committed), the file
is created `0o600` and opened with `O_NOFOLLOW` (a symlinked journal is
refused), and it rotates by size so it can't grow without bound.

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

- **Compact JSON** - results are serialized without indentation, one text block per call
  (measured: 33% fewer characters than pretty-printed output across all tools on a sample binary)
- **No empty fields** - false flags, empty tag lists and null context are omitted
- **Slices, not dumps** - `code("func,var", what="pcode")` returns only the ops a value flows into
  (on `ws2_32.dll` `WSAStartup`: ~1.9K characters vs ~22K for the full listing)
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

The proxy auto-starts the backend on first use, and a file lock plus a port check stop concurrent proxies from spawning duplicates. The backend keeps running until `pyghidra-lite stop`; binaries idle for 30 minutes are unloaded from memory (the 2 most recent stay loaded) and reload transparently from disk.

> [!IMPORTANT]
> The proxy reuses whatever backend is already listening, whatever its version. After
> upgrading pyghidra-lite, run `pyghidra-lite stop` so the next session starts the new
> code. (`serve` and the Claude Code plugin run one server per session and don't have
> this issue.)

| Command | What it does |
|---------|-------------|
| `pyghidra-lite` | Stdio proxy (default) -- auto-starts backend |
| `pyghidra-lite serve` | Direct stdio server (1 JVM per session) |
| `pyghidra-lite serve -t streamable-http` | Start persistent HTTP backend manually |
| `pyghidra-lite stop` | Stop the shared backend |
| `pyghidra-lite doctor [--json]` | Diagnose the environment (read-only; exit 1 if analysis would fail) |

Set `PYGHIDRA_LITE_NO_AUTOSTART=1` to disable auto-start (useful with systemd).

## Configuration

Every setting is a `serve` flag or an environment variable (handy in an MCP `env` block):

| Variable | Flag | Default | Purpose |
|:---|:---|:---|:---|
| `GHIDRA_INSTALL_DIR` | `--ghidra-dir` | auto-detect | Ghidra installation |
| `PYGHIDRA_LITE_PROJECT_DIR` | `--project-dir` | see [below](#multi-agent-support) | Analysis cache |
| `PYGHIDRA_LITE_RESTRICT_PATHS` | `--restrict-path` (repeatable) | unrestricted | Only load binaries under these dirs (env: OS path separator) |
| `PYGHIDRA_LITE_ALLOW_WRITE` | `--allow-write` | off | Enable `annotate` (still human-confirmed) |
| `PYGHIDRA_LITE_DEFAULT_PROFILE` | `--profile` | `fast` | Default analysis profile |
| `PYGHIDRA_LITE_TOOL_TIMEOUT` | &mdash; | `300` seconds | Per-call budget so a wedged JVM call can't hang the client; `0` disables |
| `PYGHIDRA_LITE_AUTH_TOKEN` | `--auth-token` | none | Bearer token for HTTP transports (required off-loopback) |
| `PYGHIDRA_LITE_NO_AUTOSTART` | &mdash; | off | Proxy never spawns a backend |
| &mdash; | `--evict-after` / `--min-loaded` | `30` min / `2` | Memory eviction of idle binaries |
| &mdash; | `--autopurge-days` | off | Delete projects not opened in N days |

## Multi-Agent Support

Each binary gets its own Ghidra project, enabling:

- Parallel analysis of different binaries
- Shared results across agents
- Persistent analysis (survives restarts)
- Content-addressed storage (same binary = same analysis)

Projects are stored in `~/pyghidra-lite/projects/` (Windows: `%LOCALAPPDATA%\pyghidra-lite\projects\`),
or in the pre-0.8 location `~/.local/share/pyghidra-lite/projects/` if that already exists.
Override with `--project-dir` or `PYGHIDRA_LITE_PROJECT_DIR`. Ghidra 12+ rejects project paths with a
component starting with `.`, so a legacy `~/.local` directory only works with Ghidra 11.x —
`pyghidra-lite doctor` flags this.

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

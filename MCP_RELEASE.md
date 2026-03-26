# MCP Technical Reference

Technical reference for the pyghidra-lite MCP server.

## Protocol Compliance

Complies with MCP Specification 2025-11-25.

| Feature | Status |
|---------|--------|
| JSON-RPC 2.0 | Supported |
| Capability negotiation | Supported |
| Tools | 8 consolidated tools |
| `tools/list_changed` notifications | Supported |
| Resources | Binary metadata |
| Transports | stdio proxy (default), stdio direct, streamable-http, SSE |
| Progress reporting | Supported |

## Tool Surface

pyghidra-lite exposes these public MCP tools:

| Tool | Purpose | Key constrained parameters |
|------|---------|----------------------------|
| `load` | Import/analyze a binary | `profile=fast|default|deep`, `bootstrap_mode=named|all` |
| `delete` | Remove a binary/project/job | `name` |
| `binaries` | List loaded, queued, and on-disk binaries | `jobs`, `rank_sources` |
| `info` | First-contact triage and metadata | `detail=summary|full|format|sections|entropy` |
| `functions` | List/search functions and symbol views | `type=all|swift|objc|imports|exports|types|got|dylibs` |
| `code` | Decompile, disassemble, or read raw bytes/strings | `what=decompile|asm|bytes|string` |
| `xrefs` | Callers, callees, call graphs, symbol diff | `direction=to|from`, `depth<=5`, batch target max 20 |
| `search` | Strings, symbols, byte patterns, bulk discovery | `type=strings|symbols|bytes|all|blob|extract`, `mode=indexed|deep` |

All enum/range constraints are published in the MCP input schema so `tools/list` is precise for agents.

## Error Handling

Tool errors follow current MCP guidance:

- Schema/request-shape problems are handled by FastMCP validation.
- Semantic input validation and business-rule failures are surfaced as tool execution errors with `isError: true`.
- The server avoids using JSON-RPC `INVALID_PARAMS` for normal tool-level validation like ambiguous binary names, unsupported enum values, or invalid bootstrap combinations.

## Progress Reporting

`load()` reports progress for blocking imports and automatically delegates large binaries to background analysis:

- Binaries smaller than 10 MB block until analysis completes
- Binaries 10 MB and larger return quickly with `status="queued"` and a `unit_id`
- Progress/results are available through `binaries(jobs=True)`
- Blocking imports report progress every 10% or every 60 seconds

## Transport Options

### stdio proxy (default)

The default mode runs a lightweight stdio proxy that forwards to a persistent shared HTTP backend. Multiple sessions share a single JVM (~10MB per proxy vs ~500MB per direct session).

```bash
pyghidra-lite          # stdio proxy, auto-starts backend
pyghidra-lite stop     # stop the shared backend
```

The proxy auto-starts the backend on first use (`localhost:19101`) with a 30-minute idle timeout. A file lock prevents concurrent proxy starts from spawning duplicate backends.

### stdio direct

Each client gets its own JVM. Use for single-session workflows or debugging.

```bash
pyghidra-lite serve
```

### streamable-http

Persistent shared HTTP backend (what the proxy auto-starts). Use for systemd or manual management.

```bash
pyghidra-lite serve --transport streamable-http --port 19101
```

### SSE (legacy)

```bash
pyghidra-lite serve --transport sse --port 8001
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation (optional, auto-detected) |
| `PYGHIDRA_LITE_RESTRICT_PATHS` | Colon-separated path restrictions (unrestricted if unset) |
| `PYGHIDRA_LITE_DEFAULT_PROFILE` | Default `load()` profile (`fast`, `default`, `deep`) |
| `PYGHIDRA_LITE_PROJECT_DIR` | Project storage directory |
| `PYGHIDRA_LITE_RUNTIME_HOME` | Writable runtime home for Ghidra/JVM state |
| `PYGHIDRA_LITE_NO_AUTOSTART` | Set to `1` to disable proxy auto-start of backend |

## Command Line Options

```text
pyghidra-lite serve [OPTIONS] [BINARIES...]

Options:
  --ghidra-dir DIR       Ghidra installation directory (overrides env var)
  --restrict-path PATH   Restrict imports to PATH (repeatable, unrestricted if unset)
  --transport TYPE       Transport: stdio (default) or sse
  --port PORT            SSE server port (default: 8000)
  --profile PROFILE      Default analysis profile: fast/default/deep
  --project-dir DIR      Ghidra project directory
  --project-name NAME    Ghidra project name
  --runtime-home DIR     Writable runtime home for Ghidra state
  --verbose              Enable debug logging
  --version              Show version
  --help                 Show help
```

## Project Structure

```text
~/.local/share/pyghidra-lite/
└── projects/
    └── {unit_id}/
        ├── {unit_id}.gpr
        ├── {unit_id}.rep/
        ├── .analysis_status
        └── result.json        # scan job results when applicable
```

Properties:

- Content-addressed by binary content
- Per-binary project isolation
- Persistent across restarts
- Auto-hot-load of completed on-disk projects when referenced by tools

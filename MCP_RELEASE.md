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
| Transports | stdio (default), SSE |
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

### stdio (default)

Each client gets an isolated session.

```bash
pyghidra-lite serve --allow-path /path/to/binaries
```

### SSE

Shared server for multiple agents.

```bash
pyghidra-lite serve --transport sse --port 8001 --allow-path /path/to/binaries
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation (optional, auto-detected) |
| `PYGHIDRA_LITE_ALLOWED_PATHS` | Colon-separated allowed paths |
| `PYGHIDRA_LITE_ALLOW_ANY_PATH` | Set to `1` to allow any path |
| `PYGHIDRA_LITE_DEFAULT_PROFILE` | Default `load()` profile (`fast`, `default`, `deep`) |
| `PYGHIDRA_LITE_PROJECT_DIR` | Project storage directory |
| `PYGHIDRA_LITE_RUNTIME_HOME` | Writable runtime home for Ghidra/JVM state |

## Command Line Options

```text
pyghidra-lite serve [OPTIONS] [BINARIES...]

Options:
  --ghidra-dir DIR       Ghidra installation directory (overrides env var)
  --allow-path PATH      Allow imports from PATH (repeatable)
  --allow-any-path       Allow imports from any path
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

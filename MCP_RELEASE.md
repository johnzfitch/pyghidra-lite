# MCP Technical Reference

Technical details for MCP server implementation and integration.

## Protocol Compliance

Complies with [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25).

| Feature | Status |
|---------|--------|
| JSON-RPC 2.0 | Supported |
| Capability negotiation | Supported |
| Tools | 40+ tools |
| Resources | Binary metadata |
| Transports | stdio (default), SSE |
| Progress reporting | Supported |

## Transport Options

### stdio (default)

Each agent gets isolated session. No configuration needed.

```bash
pyghidra-lite --allow-path /path/to/binaries
```

### SSE (Server-Sent Events)

Shared server for multiple agents. Reduces process overhead.

```bash
pyghidra-lite --transport sse --port 8001 --allow-path /path/to/binaries
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation (required) |
| `PYGHIDRA_LITE_ALLOWED_PATHS` | Colon-separated allowed paths |
| `PYGHIDRA_LITE_ALLOW_ANY_PATH` | Set to `1` to allow any path |

## Command Line Options

```
pyghidra-lite [OPTIONS] [BINARIES...]

Options:
  --allow-path PATH      Allow imports from PATH (repeatable)
  --allow-any-path       Allow imports from any path
  --transport TYPE       Transport: stdio (default) or sse
  --port PORT            SSE server port (default: 8000)
  --profile PROFILE      Default analysis profile: fast/default/deep
  --project-dir DIR      Ghidra project directory
  --project-name NAME    Ghidra project name
  --verbose              Enable debug logging
  --version              Show version
  --help                 Show help
```

## Tool Categories

Tools are capability-gated based on binary format:

| Capability | Detected When | Tools Enabled |
|------------|---------------|---------------|
| `elf` | ELF magic bytes | `elf_*` |
| `macho` | Mach-O magic bytes | `macho_*` |
| `swift` | `__swift5_*` sections | `swift_*`, `demangle` |
| `objc` | `__objc_*` sections | `objc_*` |
| `hermes` | Hermes bytecode header | `hermes_*` |

## Progress Reporting

`import_binary` reports progress for large binaries:

- Updates sent every 10% progress OR every 60 seconds
- Phases: Loading -> Importing -> Analyzing -> Detecting capabilities -> Complete
- Prevents agent timeouts without token spam

## Project Structure

```
~/.local/share/pyghidra-lite/
└── projects/
    └── {unit_id}/           # SHA256 hash prefix
        ├── {unit_id}.gpr    # Ghidra project file
        └── {unit_id}.rep/   # Analysis repository
```

- **Content-addressed**: Same binary content = same project
- **Per-binary isolation**: No cross-binary lock contention
- **Persistent**: Analysis survives process restarts

## Error Codes

| Code | Meaning |
|------|---------|
| `-32602` | Invalid parameters (bad path, unknown profile) |
| `-32603` | Internal error (Ghidra failure, analysis timeout) |
| `-32001` | Binary not found or not imported |
| `-32002` | Function not found |

## Token Optimization

Default behavior minimizes tokens:

| Tool | Default | Verbose Flag |
|------|---------|--------------|
| `list_functions` | name, address only | `compact=false` |
| `list_exports` | name, address only | `compact=false` |
| `import_binary` | no tool list | `list_tools=true` |
| `decompile` | code only | `include_callees=true` |

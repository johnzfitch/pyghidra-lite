# Security Policy

## Supported Versions

Currently supported versions:

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Security Features

pyghidra-lite includes several security features:

### Path Restrictions
- Use `--restrict-path` to lock down to specific directories
- Required when binding to non-loopback addresses
- Environment variable: `PYGHIDRA_LITE_RESTRICT_PATHS` (colon-separated)
- Import paths are resolved to their canonical target and re-validated
  immediately before import, so a symlink swapped after the check cannot
  redirect the load outside an allowed root (TOCTOU defense-in-depth)

### Network Transport Hardening (HTTP/SSE)
- **Loopback by default**: loopback binds are detected via `ipaddress`
  (127.0.0.0/8, ::1, `localhost`), not a literal string compare
- **DNS-rebinding protection**: Host/Origin headers are validated against an
  allow-list of localhost variants plus the configured bind host. Front the
  server under another hostname with `--allowed-host host:port`
- **Bearer auth**: `--auth-token` (or `PYGHIDRA_LITE_AUTH_TOKEN`) enforces a
  constant-time token check on every HTTP request. It is **required** for
  non-loopback binds — the server has no other access control, so reaching the
  port must not be enough to call tools such as `delete`
- **Tool annotations**: every tool advertises MCP behavioral hints
  (`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`) so
  clients can apply safe auto-approve / confirmation policies

### Error Disclosure
- Outward-facing error messages are sanitized to redact server-side absolute
  paths (project dir, runtime home, home directory); full detail stays in logs

### Project Isolation
- Each binary gets isolated Ghidra project
- Per-binary locking prevents concurrent corruption
- Content-addressed storage prevents path traversal

### Binary Analysis Safety
- Ghidra runs in sandboxed JVM
- Analysis doesn't execute binary code
- Decompilation timeouts prevent resource exhaustion

## Security Considerations

### Running as MCP Server

When running pyghidra-lite as an MCP server:

1. **Path Restrictions**: Use `--restrict-path` (required for non-loopback hosts)
2. **Authentication**: Set `--auth-token` for HTTP/SSE (required for non-loopback
   binds); terminate TLS at a reverse proxy for remote access
3. **Untrusted Binaries**: Ghidra analyzes but doesn't execute binaries
4. **Resource Limits**: Set appropriate timeouts for decompilation
5. **Transport**: stdio (default) is per-session; HTTP transports are shared and
   apply DNS-rebinding protection plus optional bearer auth

### Known Limitations

1. **Malformed Binaries**: Ghidra may crash on heavily malformed files
2. **Memory Usage**: Large binaries (>500MB) require significant RAM
3. **Lock Files**: Project locks survive crashes (manual cleanup needed)

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **GitHub Security Advisories** (preferred):
   https://github.com/johnzfitch/pyghidra-lite/security/advisories/new

2. **Email**: zack@internetuniverse.org

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Fix timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 30 days
  - Medium: Within 90 days
  - Low: Next release

### Disclosure Policy

- Coordinated disclosure preferred
- Public disclosure after fix is released
- Credit given to reporter (unless anonymous requested)

## Security Best Practices

### For Users

1. **Keep Updated**: Use latest version
2. **Limit Access**: Use `--restrict-path` for shared servers
3. **Isolate Environment**: Run in containers if processing untrusted binaries
4. **Monitor Resources**: Set process limits for long-running instances

### For Developers

1. **Input Validation**: Always validate binary paths
2. **Timeout Handling**: Set appropriate timeouts
3. **Error Handling**: Don't expose internal paths in errors
4. **Dependencies**: Keep PyGhidra and dependencies updated

## Third-Party Dependencies

Security of dependencies:
- **PyGhidra**: Official Ghidra Python bindings
- **Ghidra**: NSA-developed reverse engineering tool
- **MCP SDK**: Anthropic/OpenAI maintained protocol

Report dependency vulnerabilities to their respective projects.

## Security Updates

Security updates will be:
- Announced in GitHub releases
- Documented in CHANGELOG.md
- Tagged with `[security]` prefix

Subscribe to releases for notifications:
https://github.com/johnzfitch/pyghidra-lite/releases

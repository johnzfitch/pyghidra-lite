# Security Policy

## Supported Versions

Currently supported versions:

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Security Features

pyghidra-lite includes several security features:

### Path Restrictions
- Unrestricted by default (MCP clients like Claude Code handle permissions)
- Use `--restrict-path` to lock down to specific directories
- Environment variable: `PYGHIDRA_LITE_RESTRICT_PATHS` (colon-separated)

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

1. **Path Restrictions**: Use `--restrict-path` in shared/production environments
2. **Untrusted Binaries**: Ghidra analyzes but doesn't execute binaries
3. **Resource Limits**: Set appropriate timeouts for decompilation
4. **Network Isolation**: stdio transport (default) has no network exposure

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

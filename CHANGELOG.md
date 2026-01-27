# Changelog

All notable changes to pyghidra-lite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-27

### Added
- Initial release of pyghidra-lite MCP server
- 40+ reverse engineering tools via Model Context Protocol
- Support for ELF (Linux), Mach-O (iOS/macOS), and PE binaries
- Swift demangling and analysis tools
- Objective-C class and method analysis
- Hermes (React Native) bytecode analysis
- Three analysis profiles: fast, default, deep
- Multi-agent support with per-binary project isolation
- Path-based security with allowlist controls
- Token optimization features (compact modes, opt-in tool lists)
- Comprehensive MCP compliance (stdio and SSE transports)

### Fixed
- Transaction management in reanalyze tool
- String truncation to prevent token bombs (500 char limit)

### Security
- Path allowlist prevents unauthorized file access
- Per-binary project isolation
- Environment variable configuration support

[0.1.0]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.1.0

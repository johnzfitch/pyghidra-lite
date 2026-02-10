# Changelog

All notable changes to pyghidra-lite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-09

### Added
- `--ghidra-dir` CLI flag for explicit Ghidra path override
- Auto-detection of Ghidra in common paths (`/opt/ghidra`, `/usr/share/ghidra`, `~/ghidra`, versioned installs)

### Changed
- `GHIDRA_INSTALL_DIR` env var no longer required if Ghidra is in a standard location
- Clear error message with setup instructions when Ghidra is not found

## [0.1.1] - 2026-01-29

### Added
- Async progress reporting for `import_binary` (updates every 10% or 60s)
- MCP Registry listing (`io.github.johnzfitch/pyghidra-lite`)
- AUR package (`python-pyghidra-lite`)

### Changed
- `import_binary` now runs in thread pool to avoid blocking
- Improved documentation with clearer Quick Start guide

### Removed
- Unused emulation dependencies (capstone, unicorn)

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
- Token optimization features (compact modes, opt-in metadata)

### Fixed
- Transaction management in reanalyze tool
- String truncation to prevent token overflow (500 char limit)

### Security
- Path allowlist prevents unauthorized file access
- Per-binary project isolation

[0.2.0]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.2.0
[0.1.1]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.1.1
[0.1.0]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.1.0

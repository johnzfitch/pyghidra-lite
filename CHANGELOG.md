# Changelog

All notable changes to pyghidra-lite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-05-31

### Added
- **MCP tool annotations**: every tool now publishes `ToolAnnotations`
  (`title` + `readOnlyHint` / `destructiveHint` / `idempotentHint` /
  `openWorldHint`) so clients can apply safe auto-approve / confirmation UX.
  `delete` is marked destructive; the six analysis tools are read-only and
  idempotent; `load` mutates but is non-destructive.
- **HTTP transport hardening**: DNS-rebinding protection (Host/Origin
  validation) for all HTTP/SSE binds, a static bearer-token guard via
  `--auth-token` / `PYGHIDRA_LITE_AUTH_TOKEN`, and `--allowed-host` for serving
  behind another hostname. A bearer token is now required for non-loopback binds.

### Security
- **Configuration is immutable while serving**: `ServerConfig` is now frozen,
  built once at startup through a single writer (`configure_server`), and locked
  at the serve boundary (`go_live()`). Any attempt to change a security setting
  (restrict paths, bind host, auth, runtime home) mid-session raises
  `ConfigLockedError` -- to change one you stop the process and re-run the CLI.
  This closes the runtime config-tamper/MITM surface.
- **Removed run-time remote code execution**: `search(type="extract")` no longer
  runs `bun x bun-extract-bundled`, which resolved and executed an npm package
  from the network on every call. It now invokes a locally pre-installed, pinned
  extractor directly (fixed argv, no shell, no package-manager launcher), or
  returns an actionable error.

### Changed
- `info`, `code`, and `xrefs` are now async and run their blocking Ghidra work
  off the event loop (via `asyncio.to_thread`), so a single decompile no longer
  freezes the whole shared HTTP server; `functions` and `search` offload their
  blocking work the same way.
- `GhidraTools` is cached per binary handle, so its function-name index and list
  caches survive between calls instead of being rebuilt every time.
- Loopback bind detection uses `ipaddress` (127.0.0.0/8, ::1, `localhost`)
  instead of a literal `127.0.0.1` string compare.
- Outward-facing error messages redact server-side absolute paths.

### Fixed
- Import paths are re-validated against the restrict roots immediately before
  import (TOCTOU defense-in-depth); the "path not allowed" error now reports
  both the requested path and where it resolved to.
- Background search/extract jobs are bounded by the same queue cap as analysis
  jobs, preventing unbounded `_active_jobs` growth.
- `xrefs(depth>1)` call graphs are capped (max nodes/edges) and flagged as
  `truncated` instead of returning unbounded payloads.
- `load()` caches the binary content hash by `(path, mtime, size)` so an
  already-analyzed binary isn't re-hashed from scratch on every call.
- Removed a dead `depth = min(depth, 5)` line in `xrefs` that shadowed the
  closure variable (would raise `UnboundLocalError` on `depth>1`).
- Both id validators now anchor with `\Z` instead of `$`. `^[0-9a-f]{16}$`
  accepted a trailing newline (Python's `$` also matches just before a final
  `\n`), so `"<unit_id>\n"` passed as a valid id.
- `_init_backend` no longer mutates `runtime_home` on the config object in place
  -- a write that previously ran inside the lifespan, after the server was
  already live. The resolved runtime home is persisted before config is locked.

### Tests
- Added an adversarial red-team suite (`tests/test_red_team.py`) that performs
  each attack and asserts it fails closed: restrict-path escape + TOCTOU, id
  injection, a live trojan-on-PATH trap proving extraction never runs a package
  launcher, DNS-rebinding rejected `421` end-to-end through the real ASGI app,
  the auth-bypass matrix, loopback fail-closed, job-queue cap, error redaction,
  and holder-impenetrability checks (config cannot be mutated while live, plus a
  tripwire that fails if any `@mcp.tool` gains a settings-mutation surface).
- Added a real-server end-to-end suite (`tests/test_security_e2e.py`, gated by
  `PYGHIDRA_E2E`) and a `security-e2e` CI workflow (JDK 21 + pinned Ghidra) that
  boots an actual `pyghidra-lite serve` and attacks it over real TCP sockets.

## [0.5.1] - 2026-03-12

### Changed
- Public MCP surface remains the 8 consolidated tools: `load`, `delete`, `binaries`, `info`, `functions`, `code`, `xrefs`, `search`
- Tool docstrings now describe the current consolidated workflows exposed through `tools/list`
- MCP input schemas now publish enum/range constraints for `load.profile`, `load.bootstrap_mode`, `info.detail`, `functions.type`, `code.what`, `xrefs.direction`, `xrefs.depth`, `xrefs.target[]`, `search.type`, `search.mode`, and `search.query`

### Fixed
- Semantic validation and business-rule failures now surface as MCP tool execution errors instead of being modeled like JSON-RPC parameter errors
- Invalid enum values no longer silently fall back to default behaviors in `info`, `functions`, `code`, `xrefs`, and `search`
- Capability-mismatch failures in `functions()` now fail as real tool errors instead of returning `{"error": ...}` inside successful payloads
- Removed the dead `src/pyghidra_lite/consolidated.py` alias layer and synced technical docs to the actual 8-tool server

## [0.5.0] - 2026-03-03

### Added
- **`detect_embedded_runtime` tool**: Identifies embedded runtime payloads (Bun/BunFS,
  Electron ASAR, Node SEA, PyInstaller, UPX, V8 snapshot, Lua bytecode) with confidence
  ratings and recommended search strategies (`external_tools`, `search_payload`,
  `unpack_first`). Replaces 8+ exploratory tool calls with one definitive answer.
- **`search_strings_deep` tool**: Raw memory scan for printable ASCII strings, bypassing
  Ghidra's defined-string list. Useful for lightly-analyzed sections. Supports section
  filtering and optional high-entropy skip.
- **`batch_search_strings` tool**: Searches up to 20 patterns in one call. Reads memory
  blocks once and scans all queries simultaneously. Returns `{query: count}` compact or
  `{query: hits[]}` verbose.
- **`extract_strings_from_blob` tool**: Extracts strings from a raw memory region without
  decompression. Accepts `payload_offset` from `detect_embedded_runtime` for uncompressed
  payloads (ASAR, Node SEA).
- **`StringXref.section`**: Section provenance (`.rodata`, `.strtab`, etc.) added to all
  `search_strings` results. Non-breaking -- field defaults to None.
- **`EmbeddedRuntime` model**: New model for runtime detection results with `type`,
  `confidence`, `strategy`, and optional `payload_offset`.

## [0.4.0] - 2026-03-01

### Added
- **`decompile_with_cfg` tool**: Returns decompiled pseudo-code plus control flow graph in one call, enabling LLM clients to infer types from structure
- **MCP Registry workflow**: Automated publishing via GitHub Actions OIDC

### Changed
- **10x faster DEFAULT profile**: Disabled Decompiler Parameter ID by default
- **Smart demangler selection**: ELF/Mach-O disables Microsoft demangler, PE disables GNU demangler
- **JVM heap tuning**: Raised auto-size cap from 8GB to 16GB, set -Xms equal to -Xmx when --jvm-heap specified
- **Hot-load on import**: Previously-analyzed binaries detected and loaded immediately

### Fixed
- `find_bytes`: Fixed OOM on large search patterns
- `diff_symbols`: Resolved O(n^2) sort inefficiency
- `entropy_map`: Improved accuracy for small sections
- `search_all`: Fixed crash on malformed regex
- Stale Ghidra lock files now swept on server startup

### Security
- Closed several denial-of-service vectors in search tools

## [0.3.0] - 2026-02-10

### Added
- **Async binary analysis**: `analyze_binary` MCP tool returns in <1s, runs analysis in isolated subprocess workers
- **Analysis polling**: `analysis_status` MCP tool for progress tracking with auto-hot-loading on completion
- **Job cancellation**: `cancel_analysis` MCP tool to kill in-progress analysis workers
- **CLI subcommands**: `pyghidra-lite import` (offline batch analysis), `pyghidra-lite list` (inspect cached projects), `pyghidra-lite serve` (MCP server, backward-compatible default)
- **Filesystem watcher**: hot-loads completed analyses into running server via watchdog
- **Crash recovery**: detects stale/dead workers on startup, periodic background monitor
- **Time estimation**: per-profile analysis time estimates with self-calibration logging
- **Worker isolation**: subprocess workers with auto-sized JVM heap (2-8GB based on binary size)
- `--max-workers` flag to control concurrent analysis workers (default 4)
- `--jvm-heap` flag on import subcommand for manual heap control
- `--status-file` flag for subprocess worker progress reporting
- `list_binaries` now shows in-progress jobs and on-disk projects from previous runs

### Changed
- `_capabilities` dict now keyed by `unit_id` instead of program name (fixes name collision bugs)
- `_init_program_handle` accepts optional `unit_id` parameter (avoids wasteful recomputation)
- `import_binary` detects previously-analyzed projects and skips redundant re-analysis
- `import_binary` MCP tool marked as deprecated in favor of `analyze_binary`

### Dependencies
- Added `watchdog>=3.0.0` for filesystem event monitoring

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

[0.4.0]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.4.0
[0.3.0]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.3.0
[0.2.0]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.2.0
[0.1.1]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.1.1
[0.1.0]: https://github.com/johnzfitch/pyghidra-lite/releases/tag/v0.1.0

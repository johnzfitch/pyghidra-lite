# pyghidra-lite Optimization Handoff

## Summary

Code review and optimization session focused on performance, reliability, token efficiency, and multi-agent support.

## Changes Made

### 1. Performance Optimizations

**tools.py**
- Added function caching with 5-minute TTL (`_functions_cache`, `_functions_cache_time`)
- Added function name index for O(1) lookups (`_build_function_index()`)
- Single-pass `_find_function()` - no longer iterates twice
- Deferred string detection from `list_functions` to individual function queries
- Added `include_metadata` parameter to skip expensive ref counting

**backend.py**
- Added `compute_unit_id_streaming()` - streams file in 64KB chunks instead of loading entire binary into memory
- Changed `start()` to lazy-load projects by default (`eager_load=False`) - critical for multi-agent support

**server.py**
- Rewrote `detect_capabilities()` to use fast section-name heuristics instead of symbol iteration
- Old: O(symbols) iteration for Swift/ObjC/Hermes detection
- New: O(blocks) check on memory block names

**swift.py**
- Fixed `get_swift_info()` to batch demangle all symbols at once instead of individual subprocess calls
- Added proper error handling for `subprocess.SubprocessError`

### 2. Bug Fixes

**tools.py, elf.py, macho.py**
- Fixed `getPermissions()` bug - Ghidra's MemoryBlock uses `isRead()`, `isWrite()`, `isExecute()` not `getPermissions()`

### 3. New MCP Tools

**server.py + tools.py**
- `batch_decompile(binary, functions, ...)` - Decompile multiple functions in one call
- `call_graph(binary, function, depth, direction)` - Get call graph with configurable depth
- `memory_map(binary)` - Get memory layout with permissions

### 4. Token Efficiency

**server.py**
- `import_binary`: Added `list_tools=False` - tool list only on request
- `list_functions`: Added `include_metadata=False` default, uses `addr` instead of `address`
- `decompile`: Added `include_callees`, `include_strings`, `include_provenance` params
- `read_bytes`: Added `include_provenance` parameter
- Shortened error messages throughout

### 5. Reliability

- Added debug logging for silent exceptions
- Fixed all exception chaining with `from exc`
- Added `subprocess.SubprocessError` handling in swift.py

### 6. Packaging

**pyproject.toml**
- Removed unused `lief` dependency
- Added `emulation` optional group for capstone/unicorn
- Added project URLs
- Enhanced ruff config with more lint rules

**__init__.py**
- Added `GhidraTools` and `ElfTools` to exports

## Performance Results

| Metric | Before | After |
|--------|--------|-------|
| CPU during idle | 100% constant | 65% dropping |
| Capability detection | O(symbols) | O(blocks) |
| Function lookup | O(n) x2 | O(1) indexed |
| Multi-agent support | Broken (locks) | Works (lazy load) |
| Decompiler activity | Idle while Python spins | Active when needed |

## Files Modified

- `src/pyghidra_lite/tools.py` - Caching, new tools, bug fixes
- `src/pyghidra_lite/backend.py` - Streaming hash, lazy loading
- `src/pyghidra_lite/server.py` - Fast capability detection, new MCP tools, token efficiency
- `src/pyghidra_lite/swift.py` - Batch demangling, error handling
- `src/pyghidra_lite/elf.py` - getPermissions fix
- `src/pyghidra_lite/macho.py` - getPermissions fix
- `src/pyghidra_lite/__init__.py` - Updated exports
- `pyproject.toml` - Cleaned dependencies, added lint rules

## Known Issues / Future Work

1. **Cumulative CPU still high** (~65%) - This is cumulative over process lifetime, drops as process idles. Initial Ghidra analysis is unavoidable.

2. **One decompiler per binary** - PyGhidra design, not easily changed. Could consider shared decompiler pool.

3. **Lock contention** - Per-binary locking prevents corruption but blocks concurrent access to same binary by multiple agents. Workaround: agents use different binaries.

## Testing

All changes pass `ruff check`. Servers need restart to pick up changes:
```bash
pkill -f pyghidra-lite
# Agents will restart servers automatically
```

---
name: reverse-engineering
description: Reverse engineer native binaries (ELF, Mach-O, PE; Swift, Objective-C, React Native/Hermes) with the pyghidra-lite Ghidra tools - triage, find the code behind a behavior, decompile, trace calls and data flow, recover struct layouts, and record findings. Use when the user asks what a binary/library/app does, how a feature or protocol is implemented, where a string/API/constant is used, to compare two builds, or to analyze malware/CTF/firmware executables.
---

# Reverse engineering with pyghidra-lite

The pyghidra-lite MCP server exposes nine tools: `load`, `binaries`, `info`, `functions`,
`code`, `xrefs`, `search`, `annotate`, `delete`. Every tool except `load` and
`binaries` takes `binary` = the name `load` returned (or its unit_id).

## Ground rules

- Decompiler output is **pseudocode inferred by Ghidra**, not source. Say so when you
  quote it, and confirm claims about exact behavior against `code(what="asm")`.
- Report what the evidence shows: function name + address for every claim, so the user
  can check it. If something was not found, say where you looked.
- Stay read-only unless the user asks to record findings (see "Recording findings").
- Prefer narrow calls. Each mode below is sized to answer one question; avoid dumping
  whole listings into context.

## 1. Load

```
load(path="/abs/path/to/binary")                 # profile="fast" (default)
```

- `fast` is right for first contact. Re-load with `profile="default"` for better types
  and decompilation, or `"deep"` for packed/obfuscated code where functions are missing.
- Binaries >= 10 MB analyze in the background: `load` returns `status="queued"`; poll
  `binaries(jobs=True)` until the analysis_id shows complete. Cached analyses return
  instantly; `fresh=True` discards a stale one.
- If `load` fails before analysis, run `pyghidra-lite doctor` in a shell (Ghidra/JDK/
  project-dir checks with fixes). Ghidra 12 rejects project dirs containing a folder that
  starts with `.`.

## 2. Triage (answer "what is this?")

```
info(binary)                                     # format, arch, counts, capabilities
info(binary, detail="full")                      # + top functions by refs, suspicious imports, notable strings
functions(binary, type="imports")                # capability tags: network/crypto/file/process/memory
functions(binary, type="exports")
search(binary, "http")                           # strings, with the functions that reference them
```

- `detail="entropy"` flags packed/encrypted sections; `detail="format"` gives ELF/Mach-O/PE
  structure. `functions(type="swift"|"objc")` and `info(detail="full")` cover Swift/ObjC
  metadata; Hermes/React Native and embedded runtimes (Bun, Node SEA, Electron,
  PyInstaller) are detected automatically.

## 3. Find the code behind a behavior

Work from an observable anchor - a string, an import, an export, a constant - to code:

```
search(binary, ["error text", "api/v1"])         # batch up to 20 queries in one call
search(binary, "connect", type="symbols")
search(binary, "deadbeef", type="bytes")         # magic numbers / crypto constants
xrefs(binary, "send")                            # who references this function/symbol/address
functions(binary, query="parse")
```

String results already list the referencing functions - go straight to `code` on them.

## 4. Read code

```
code(binary, "FUN_00401a20")                     # pseudo-C + callers + callees + strings
code(binary, ["a", "b", "c"])                    # batch decompile
code(binary, "main", cfg=True)                   # + basic blocks/edges (loops, branches)
code(binary, "main", what="asm")                 # "addr: instruction" lines (up to 400)
xrefs(binary, "main", direction="from", depth=3) # call tree: nodes + "caller -> callee" edges
```

Targets are a function name or a `0x`-prefixed address. Names are resolved as symbols
first, so a function called `add` or `dead` is never mistaken for address 0xadd.

## 5. Trace data flow

To see where a value goes - an argument, a buffer, a return value - use the p-code slice
instead of reading the whole function:

```
code(binary, "WSAStartup,param_2", what="pcode") # only the ops param_2's value flows into
code(binary, "parse_header", what="pcode")       # full SSA listing (first 400 lines)
```

- Output is SSA: each value prints as `name.id` and is defined exactly once, so search a
  token to find its definition and every use. Blocks open with `B<i> -> B<j>,B<k>:`.
- `STORE ram, <ptr>, <value>` writes memory (struct field writes show up as
  `PTRADD param_N, <index>, <elem size>` feeding a STORE); `CALL f, args...` shows which
  argument slots a value reaches; `MULTIEQUAL` merges values from different paths.
- `"func,param_2"` seeds every SSA version of param_2; `"func,param_2.226"` seeds one.
  A slice follows copies, merges and loops but not into callees - slice the callee next.

## 6. Data, layouts and file patching

```
search(binary, "sockaddr", type="types")         # struct members "offset type name", enums, typedefs
search(binary, "*", type="types", limit=50)      # what types the program has
code(binary, "0x4011a0,64", what="bytes")        # hex + ascii + file_offset + block (section)
code(binary, "0x405000", what="string")          # full null-terminated string
```

`file_offset` is where those bytes sit in the original file (null for .bss/unbacked
memory) - use it when the user wants to patch or carve the binary.

## 7. Compare builds

```
load("/path/new.bin", bootstrap="old.bin-...")   # carry names over from an analyzed older build
xrefs(binary, "other.bin-...", diff=True)        # symbols added/removed between two binaries
binaries(rank_sources=True)                      # which loaded binary has the most transferable names
```

## Recording findings (annotate)

`annotate` renames functions, sets comments and fixes prototypes. It works only if the
server was started with writes allowed (plugin setting "Allow annotate"), and every
change asks the user to confirm. Use it when the user asks to record findings, one clear
change at a time:

```
annotate(binary, "FUN_00401a20", action="rename", name="parse_header")
annotate(binary, "parse_header", action="prototype", prototype="int parse_header(uint8_t *buf, size_t len)")
annotate(binary, "parse_header", action="comment", comment="validates v2 magic, then length")
```

## Answer shape

Lead with the answer, then the evidence chain: anchor (string/import/constant) -> functions
(name @ address) -> the relevant pseudocode/asm/p-code lines -> what is still unknown.
Distinguish what the code shows from what you infer.

"""End-to-end analysis-tool tests against a REAL JVM + Ghidra.

Covers code(what="pcode"/"bytes"/"asm"), search(type="types"), and name
resolution for hex-looking names, on a freshly compiled sample.

Gated by PYGHIDRA_E2E; needs JDK 21 + Ghidra + a C compiler:
    PYGHIDRA_E2E=1 GHIDRA_INSTALL_DIR=/opt/ghidra uv run pytest tests/test_analysis_e2e.py -v
"""
import asyncio
import contextlib
import json
import os
import shutil
import subprocess
import textwrap

import pytest

from pyghidra_lite import server
from pyghidra_lite.backend import GhidraBackend
from pyghidra_lite.models import AnalysisProfile
from pyghidra_lite.server import ServerConfig

pytestmark = pytest.mark.skipif(
    not os.getenv("PYGHIDRA_E2E"),
    reason="real-JVM E2E; needs JDK+Ghidra. Set PYGHIDRA_E2E=1 to run.",
)

SOURCE = """
    #include <stdio.h>
    int add(int a, int b) { return a + b; }
    int clamp(int v, int lo, int hi) { if (v < lo) return lo; if (v > hi) return hi; return v; }
    int main(void) {
        printf("%d\\n", add(2, 3) + clamp(add(1, 1), 0, 9));
        return 0;
    }
"""


@pytest.fixture(scope="module")
def loaded(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler available to build the sample binary")
    work = tmp_path_factory.mktemp("analysis_e2e")
    src = work / "sample.c"
    src.write_text(textwrap.dedent(SOURCE))
    binary = work / "sample.bin"
    subprocess.run([cc, "-O0", "-fno-inline", "-o", str(binary), str(src)], check=True)

    saved = (server._server_config, server._config_live, server._backend)
    server._server_config = ServerConfig(project_dir=work, shared=True)
    server._config_live = True
    backend = GhidraBackend(project_dir=work, shared=True)
    server._backend = backend
    try:
        handle = backend.import_binary(binary, AnalysisProfile.FAST, analyze=True)
        server._ensure_capabilities(handle)
        yield handle, binary
    finally:
        with contextlib.suppress(Exception):
            backend.close()
        server._server_config, server._config_live, server._backend = saved


def _call(tool, **kw):
    return asyncio.run(getattr(server, tool)(ctx=None, **kw))


def test_hex_looking_name_resolves_as_symbol(loaded):
    handle, _ = loaded
    # "add" is valid hex (0xadd); it must resolve to the function, not 0xadd.
    refs = _call("xrefs", binary=handle.name, target="add")["references"]
    assert any(r.get("from_func") == "main" and "CALL" in r["type"] for r in refs)


def test_decompile_reports_callers(loaded):
    handle, _ = loaded
    res = _call("code", binary=handle.name, target="add")
    assert "\r" not in res["code"]
    assert {c["name"] for c in res["callers"]} == {"main"}


def test_pcode_is_block_ordered_ssa(loaded):
    handle, _ = loaded
    res = _call("code", binary=handle.name, target="clamp", what="pcode")
    ops = res["ops"]
    assert ops[0].startswith("B0")
    assert any(" -> " in line for line in ops if line.startswith("B"))  # branches present
    assert any("MULTIEQUAL" in line for line in ops)                    # merge of return paths
    assert any("RETURN" in line for line in ops)
    assert res["truncated"] is False
    # SSA: every defined token is defined exactly once.
    defs = [line.split(": ", 1)[1].split(" = ", 1)[0] for line in ops
            if not line.startswith("B") and " = " in line]
    assert len(defs) == len(set(defs))


def test_bytes_file_offset_matches_file(loaded):
    handle, binary = loaded
    res = _call("code", binary=handle.name, target="main,16", what="bytes")
    assert res["file_offset"] is not None and res["block"]
    raw = binary.read_bytes()[res["file_offset"]:res["file_offset"] + 16]
    assert raw.hex() == res["hex"]


def test_asm_lines_and_no_truncation_flag_for_small_function(loaded):
    handle, _ = loaded
    res = _call("code", binary=handle.name, target="add", what="asm")
    assert res["instructions"] and ": " in res["instructions"][0]
    assert "truncated" not in res


def test_search_types(loaded):
    handle, _ = loaded
    res = _call("search", binary=handle.name, query="*", type="types", limit=500)
    assert res["total"] >= len(res["types"]) > 0
    assert any(t["kind"] == "builtin" for t in res["types"])
    # The DTM only holds types this program uses, so query a name it listed.
    name = res["types"][0]["name"]
    one = _call("search", binary=handle.name, query=name.upper(), type="types", limit=1)
    assert len(one["types"]) == 1 and name.lower() in one["types"][0]["name"].lower()
    assert one["truncated"] == (one["total"] > 1)


def test_results_serialize_compact(loaded):
    from mcp.server.fastmcp.utilities import func_metadata

    handle, _ = loaded
    res = _call("info", binary=handle.name)
    text = func_metadata._convert_to_content(res)[0].text
    assert "\n" not in text and json.loads(text) == json.loads(json.dumps(res, default=str))

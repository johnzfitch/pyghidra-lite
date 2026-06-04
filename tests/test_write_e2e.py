"""End-to-end write-tool tests against a REAL JVM + Ghidra.

These exercise the actual Ghidra write paths that the JVM-free unit tests in
tests/test_write_tools.py cannot reach: startTransaction / setName / setComment,
ApplyFunctionSignatureCmd, the project save in GhidraBackend.save_program, and
reading the change back off a real Program.

Gated by PYGHIDRA_E2E (set in the security-e2e CI job); needs JDK 21 + Ghidra.

Run locally on a host with JDK 21 + Ghidra:
    PYGHIDRA_E2E=1 GHIDRA_INSTALL_DIR=/opt/ghidra uv run pytest tests/test_write_e2e.py -v
"""
import asyncio
import contextlib
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from pyghidra_lite import server
from pyghidra_lite.backend import GhidraBackend
from pyghidra_lite.models import AnalysisProfile
from pyghidra_lite.server import ServerConfig

pytestmark = pytest.mark.skipif(
    not os.getenv("PYGHIDRA_E2E"),
    reason="real-JVM write E2E; needs JDK+Ghidra. Set PYGHIDRA_E2E=1 to run.",
)


class _AcceptCtx:
    """MCP context whose elicitation prompt always accepts (confirm=True)."""

    class _Session:
        def check_client_capability(self, _cap):
            return True

    def __init__(self):
        self.session = self._Session()

    async def elicit(self, message, schema):
        from mcp.server.elicitation import AcceptedElicitation
        return AcceptedElicitation(data=schema(confirm=True))


class _DeclineCtx(_AcceptCtx):
    """Context whose elicitation prompt always declines."""

    async def elicit(self, message, schema):
        from mcp.server.elicitation import DeclinedElicitation
        return DeclinedElicitation()


def _compile_sample(dst_dir: Path) -> Path:
    """Compile a tiny unstripped ELF with known, separate function names."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler available to build the sample binary")
    src = dst_dir / "sample.c"
    src.write_text(textwrap.dedent("""
        #include <stdio.h>
        int add(int a, int b) { return a + b; }
        int sub(int a, int b) { return a - b; }
        int mul(int a, int b) { return a * b; }
        int dbl(int a) { return a + a; }
        int main(void) { printf("%d\\n", add(2, 3) - sub(5, 1) + mul(2, 2) + dbl(1)); return 0; }
    """))
    out = dst_dir / "sample.elf"
    # -O0 -fno-inline keeps each function as its own symbol in the symbol table.
    subprocess.run([cc, "-O0", "-fno-inline", "-o", str(out), str(src)], check=True)
    return out


@pytest.fixture(scope="module")
def loaded(tmp_path_factory):
    """Real, write-enabled backend with the sample binary imported and analyzed."""
    work = tmp_path_factory.mktemp("write_e2e")
    binary_path = _compile_sample(work)

    # Wire the server globals to a write-enabled, isolated backend, saving the
    # originals so this module can't leak state into other tests. (Setting the
    # config directly is fine in-process; the immutability contract is about the
    # serving boundary, not unit tests.)
    saved_config = server._server_config
    saved_live = server._config_live
    saved_backend = server._backend
    server._server_config = ServerConfig(allow_write=True, project_dir=work, shared=True)
    server._config_live = True
    backend = GhidraBackend(project_dir=work, shared=True)
    server._backend = backend
    try:
        handle = backend.import_binary(binary_path, AnalysisProfile.DEFAULT, analyze=True)
        server._ensure_capabilities(handle)
        yield handle
    finally:
        with contextlib.suppress(Exception):
            backend.close()
        server._server_config = saved_config
        server._config_live = saved_live
        server._backend = saved_backend


def _func(handle, name):
    return server._tools_for(handle)._find_function(name)


def _annotate(name, ctx=None, **kw):
    return asyncio.run(server.annotate(binary=name, ctx=ctx or _AcceptCtx(), **kw))


def test_sample_has_named_functions(loaded):
    names = {f.getName() for f in loaded.program.getFunctionManager().getFunctions(True)}
    # Unstripped build -> Ghidra recovers the source names we annotate below.
    assert {"add", "sub", "mul", "dbl", "main"} <= names


def test_rename_round_trips(loaded):
    res = _annotate(loaded.name, target="add", action="rename", name="my_adder")
    assert res["applied"] is True
    assert res["old"] == "add"
    assert res["new"] == "my_adder"

    names = {f.getName() for f in loaded.program.getFunctionManager().getFunctions(True)}
    assert "my_adder" in names
    assert "add" not in names


def test_comment_round_trips(loaded):
    res = _annotate(loaded.name, target="sub", action="comment", comment="subtracts b from a")
    assert res["applied"] is True
    assert "subtracts b from a" in (_func(loaded, "sub").getComment() or "")


def test_prototype_round_trips(loaded):
    res = _annotate(loaded.name, target="mul", action="prototype",
                    prototype="long mul(long a, long b)")
    assert res["applied"] is True
    sig = str(_func(loaded, "mul").getSignature().getPrototypeString())
    assert "long" in sig


def test_decline_writes_nothing(loaded):
    before = _func(loaded, "dbl").getName()
    res = _annotate(loaded.name, ctx=_DeclineCtx(), target="dbl", action="rename", name="nope")
    assert res["applied"] is False
    assert _func(loaded, "dbl").getName() == before == "dbl"


def test_disabled_when_allow_write_false(loaded):
    from mcp.shared.exceptions import McpError
    saved = server._server_config
    server._server_config = ServerConfig(
        allow_write=False, project_dir=saved.project_dir, shared=True,
    )
    try:
        with pytest.raises(McpError):
            _annotate(loaded.name, target="main", action="rename", name="x")
        assert _func(loaded, "main").getName() == "main"
    finally:
        server._server_config = saved


def test_rename_persists_across_save(loaded):
    """The committed rename is written to the on-disk project, not just memory."""
    _annotate(loaded.name, target="sub", action="rename", name="my_subber")
    # save_program ran inside the commit; the program's domain file should be
    # marked saved (no pending changes) after a successful annotate.
    df = loaded.program.getDomainFile()
    assert not df.isChanged(), "annotate should persist the change (domain file still dirty)"
    assert _func(loaded, "my_subber") is not None

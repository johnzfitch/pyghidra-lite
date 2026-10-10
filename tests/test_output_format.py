"""Output-shape and token-efficiency behaviour that needs no JVM."""

import pytest

from pyghidra_lite import server  # noqa: F401  (installs the compact converter)
from pyghidra_lite.tools import GhidraTools, get_capability_tags


@pytest.mark.parametrize("name,expected", [
    ("TlsGetValue", []),             # Windows thread-local storage, not TLS crypto
    ("TLS_client_method", ["crypto"]),
    ("GetCPInfo", []),               # substring "tcp" used to tag this network
    ("destroy_window", []),          # substring "des" used to tag this crypto
    ("CreateThread", ["process"]),   # substring "read" used to add file
    ("recvfrom", ["network"]),       # prefix match keeps recv* working
    ("sendto", ["network"]),
    ("x509_verify", ["crypto"]),
    ("SHA256_Init", ["crypto"]),
    ("BCryptHashData", ["crypto"]),
    ("_aligned_malloc", ["memory"]),
    ("status_get", []),              # "stat" must be a whole token
    ("ReadFile", ["file"]),
])
def test_capability_tags_match_tokens(name, expected):
    assert get_capability_tags(name) == expected


def test_tool_text_is_compact_single_block():
    from mcp.server.fastmcp.utilities import func_metadata

    blocks = func_metadata._convert_to_content({"a": 1, "b": [1, 2]})
    assert [b.text for b in blocks] == ['{"a":1,"b":[1,2]}']
    # A returned list is one JSON array, not one pretty block per item.
    blocks = func_metadata._convert_to_content([{"n": 1}, {"n": 2}])
    assert [b.text for b in blocks] == ['[{"n":1},{"n":2}]']
    assert func_metadata._convert_to_content("plain")[0].text == "plain"


class _Addr:
    def __init__(self, a):
        self.a = a

    def __str__(self):
        return self.a


class _Func:
    def __init__(self, name, addr, callees=(), external=False, thunk=False):
        self.name, self.addr, self.callees = name, addr, list(callees)
        self.external, self.thunk = external, thunk

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return _Addr(self.addr)

    def isExternal(self):
        return self.external

    def isThunk(self):
        return self.thunk

    def getCalledFunctions(self, _monitor):
        return self.callees


def test_call_graph_keeps_same_named_functions_distinct():
    text_a = _Func(".text", "1000")
    text_b = _Func(".text", "2000")
    ext = _Func("ExitProcess", "EXTERNAL:1", external=True)
    main = _Func("main", "3000", callees=[text_a, text_b, ext, text_a])

    tools = GhidraTools.__new__(GhidraTools)
    tools._find_function = lambda _name: main
    g = tools.get_call_graph("main", depth=1, direction="callees")

    assert g["nodes"] == [
        {"name": "main", "address": "3000"},
        {"name": ".text", "address": "1000"},
        {"name": ".text@2000", "address": "2000"},
        {"name": "ExitProcess", "address": "EXTERNAL:1", "external": True},
    ]
    # One edge per distinct caller/callee pair.
    assert g["edges"] == ["main -> .text", "main -> .text@2000", "main -> ExitProcess"]

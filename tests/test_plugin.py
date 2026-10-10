"""The Claude Code plugin must stay in lockstep with the package version."""

import json
import re
import tomllib
from pathlib import Path

import pyghidra_lite

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "pyghidra-lite"


def test_versions_in_sync():
    pkg = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    server = json.loads((ROOT / "server.json").read_text())
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    mcp = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]["pyghidra-lite"]

    pins = [a for a in mcp["args"] if a.startswith("pyghidra-lite==")]
    assert pins, "plugin .mcp.json must pin pyghidra-lite==<version>"
    assert {
        pkg,
        pyghidra_lite.__version__,
        server["version"],
        *(p["version"] for p in server["packages"]),
        manifest["version"],
        pins[0].split("==", 1)[1],
    } == {pkg}


def test_plugin_env_references_declared_options():
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    mcp = (PLUGIN / ".mcp.json").read_text()
    used = set(re.findall(r"\$\{user_config\.(\w+)\}", mcp))
    assert used and used <= set(manifest["userConfig"])


def test_marketplace_points_at_plugin():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    (entry,) = market["plugins"]
    assert (ROOT / entry["source"]).resolve() == PLUGIN.resolve()
    assert (PLUGIN / "skills" / "reverse-engineering" / "SKILL.md").is_file()

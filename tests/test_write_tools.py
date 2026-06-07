"""Tests for the opt-in, human-confirmed `annotate` write tool.

These run without a JVM/Ghidra: they exercise the gating, validation, and the
elicitation fail-closed logic by mocking the handle layer and the MCP context.
The actual transaction/persist happens inside a closure that needs a live
program, so the orchestration tests assert *that* commit is (or is not) invoked
rather than re-implementing Ghidra.
"""
import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, ErrorData

from pyghidra_lite import server
from pyghidra_lite.server import ServerConfig, _confirm_or_refuse, _ConfirmWrite


class _FakeSession:
    def __init__(self, supports: bool):
        self._supports = supports

    def check_client_capability(self, _capability) -> bool:
        return self._supports


class _FakeCtx:
    """Minimal stand-in for the FastMCP Context used by annotate."""

    def __init__(self, supports: bool, result=None, raises=None):
        self.session = _FakeSession(supports)
        self._result = result
        self._raises = raises

    async def elicit(self, message: str, schema):  # noqa: ARG002 - signature parity
        if self._raises is not None:
            raise self._raises
        return self._result


# --------------------------------------------------------------------------- #
# Config plumbing
# --------------------------------------------------------------------------- #

def test_allow_write_defaults_false():
    assert ServerConfig().allow_write is False


def test_configure_server_sets_allow_write(monkeypatch):
    monkeypatch.setattr(server, "_server_config", ServerConfig())
    monkeypatch.setattr(server, "_config_live", False)
    server.configure_server(allow_write=True)
    assert server.get_config().allow_write is True


# --------------------------------------------------------------------------- #
# Registration & annotations
# --------------------------------------------------------------------------- #

def test_annotate_registered():
    assert "annotate" in server.mcp._tool_manager._tools


def test_annotate_is_not_read_only():
    ann = server.mcp._tool_manager._tools["annotate"].annotations
    assert ann.readOnlyHint is False
    assert ann.idempotentHint is False
    assert ann.title


# --------------------------------------------------------------------------- #
# Gating: writes are refused unless --allow-write
# --------------------------------------------------------------------------- #

def test_annotate_refuses_when_write_disabled(monkeypatch):
    monkeypatch.setattr(server, "_server_config", ServerConfig(allow_write=False))
    with pytest.raises(McpError):
        asyncio.run(server.annotate(
            binary="x", target="FUN_1", action="rename", ctx=MagicMock(), name="foo",
        ))


# --------------------------------------------------------------------------- #
# Argument validation
# --------------------------------------------------------------------------- #

def test_validate_symbol_name_rejects_empty():
    with pytest.raises(McpError):
        server._validate_symbol_name("   ")


def test_validate_symbol_name_rejects_control_chars():
    with pytest.raises(McpError):
        server._validate_symbol_name("foo\x00bar")


def test_validate_symbol_name_strips_and_accepts():
    assert server._validate_symbol_name("  parse_header ") == "parse_header"


def test_annotate_rename_requires_name(monkeypatch):
    monkeypatch.setattr(server, "_server_config", ServerConfig(allow_write=True))
    with pytest.raises(McpError):
        asyncio.run(server.annotate(
            binary="x", target="FUN_1", action="rename", ctx=MagicMock(),
        ))


def test_annotate_comment_requires_comment(monkeypatch):
    monkeypatch.setattr(server, "_server_config", ServerConfig(allow_write=True))
    with pytest.raises(McpError):
        asyncio.run(server.annotate(
            binary="x", target="FUN_1", action="comment", ctx=MagicMock(),
        ))


# --------------------------------------------------------------------------- #
# Elicitation gate (fail closed)
# --------------------------------------------------------------------------- #

def test_confirm_false_when_client_lacks_elicitation():
    ctx = _FakeCtx(supports=False)
    assert asyncio.run(_confirm_or_refuse(ctx, "rename?")) is False


def test_confirm_true_on_accept():
    ctx = _FakeCtx(supports=True, result=AcceptedElicitation(data=_ConfirmWrite(confirm=True)))
    assert asyncio.run(_confirm_or_refuse(ctx, "rename?")) is True


def test_confirm_false_on_accept_but_confirm_false():
    ctx = _FakeCtx(supports=True, result=AcceptedElicitation(data=_ConfirmWrite(confirm=False)))
    assert asyncio.run(_confirm_or_refuse(ctx, "rename?")) is False


def test_confirm_false_on_decline():
    ctx = _FakeCtx(supports=True, result=DeclinedElicitation())
    assert asyncio.run(_confirm_or_refuse(ctx, "rename?")) is False


def test_confirm_false_on_cancel():
    ctx = _FakeCtx(supports=True, result=CancelledElicitation())
    assert asyncio.run(_confirm_or_refuse(ctx, "rename?")) is False


def test_confirm_false_when_elicit_errors():
    ctx = _FakeCtx(supports=True, raises=McpError(ErrorData(code=INTERNAL_ERROR, message="boom")))
    assert asyncio.run(_confirm_or_refuse(ctx, "rename?")) is False


# --------------------------------------------------------------------------- #
# Orchestration: confirmation decides whether the commit runs
# --------------------------------------------------------------------------- #

_PREVIEW = {
    "binary": "x", "target": "FUN_1", "target_addr": "0x1000",
    "action": "rename", "old": "FUN_1", "new": "foo",
}


def test_annotate_fail_closed_skips_commit(monkeypatch):
    """No elicitation support -> preview returned, commit never runs, applied=False."""
    monkeypatch.setattr(server, "_server_config", ServerConfig(allow_write=True))
    calls = []

    async def fake_with_handle_async(action, binary, op):
        calls.append(action)
        return dict(_PREVIEW)

    monkeypatch.setattr(server, "_with_handle_async", fake_with_handle_async)
    audited = []
    monkeypatch.setattr(server, "_audit_write", lambda preview, outcome, **kw: audited.append(outcome))
    ctx = _FakeCtx(supports=False)  # cannot confirm -> fail closed

    result = asyncio.run(server.annotate(
        binary="x", target="FUN_1", action="rename", ctx=ctx, name="foo",
    ))
    assert result["applied"] is False
    assert "not confirmed" in result["reason"]
    assert calls == ["annotate"]  # only the preview op ran; commit was skipped
    assert audited == ["declined"]  # the refused attempt is journaled


def test_annotate_confirmed_runs_commit(monkeypatch):
    """User accepts -> commit op runs (second handle call) and applied=True."""
    monkeypatch.setattr(server, "_server_config", ServerConfig(allow_write=True))
    calls = []

    async def fake_with_handle_async(action, binary, op):
        calls.append(action)
        if len(calls) == 1:
            return dict(_PREVIEW)
        return {**_PREVIEW, "applied": True}

    monkeypatch.setattr(server, "_with_handle_async", fake_with_handle_async)
    audited = []
    monkeypatch.setattr(server, "_audit_write", lambda preview, outcome, **kw: audited.append(outcome))
    ctx = _FakeCtx(supports=True, result=AcceptedElicitation(data=_ConfirmWrite(confirm=True)))

    result = asyncio.run(server.annotate(
        binary="x", target="FUN_1", action="rename", ctx=ctx, name="foo",
    ))
    assert result["applied"] is True
    assert len(calls) == 2  # preview + commit
    assert audited == ["applied"]  # the committed write is journaled


# --------------------------------------------------------------------------- #
# Audit journal
# --------------------------------------------------------------------------- #

_AUDIT_PREVIEW = {
    "binary": "b", "unit_id": "u", "analysis_id": "a", "action": "rename",
    "target": "FUN_1", "target_addr": "0x1000", "old": "FUN_1", "new": "foo",
}


def test_audit_write_appends_jsonl(tmp_path, monkeypatch):
    # No backend -> _audit_log_path falls back to the config project_dir.
    monkeypatch.setattr(server, "_backend", None)
    monkeypatch.setattr(server, "_server_config",
                        ServerConfig(allow_write=True, project_dir=tmp_path))

    server._audit_write(_AUDIT_PREVIEW, "applied")
    server._audit_write({**_AUDIT_PREVIEW, "old": "foo", "new": "bar"}, "declined")

    path = tmp_path / "annotate_audit.jsonl"
    assert path.exists()
    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0]["outcome"] == "applied"
    assert lines[0]["action"] == "rename"
    assert lines[0]["old"] == "FUN_1" and lines[0]["new"] == "foo"
    assert lines[0]["addr"] == "0x1000"
    assert "ts" in lines[0]
    assert lines[1]["outcome"] == "declined"


def test_audit_write_records_detail(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_backend", None)
    monkeypatch.setattr(server, "_server_config",
                        ServerConfig(allow_write=True, project_dir=tmp_path))
    server._audit_write(_AUDIT_PREVIEW, "failed", detail="boom")
    rec = json.loads((tmp_path / "annotate_audit.jsonl").read_text().splitlines()[0])
    assert rec["outcome"] == "failed"
    assert "boom" in rec["detail"]


def test_audit_write_never_raises(monkeypatch):
    # A broken journal path must not be able to break (or block) a tool call.
    def boom():
        raise OSError("nope")
    monkeypatch.setattr(server, "_audit_log_path", boom)
    server._audit_write(_AUDIT_PREVIEW, "applied")  # must not raise


def test_audit_write_rejects_symlink(tmp_path, monkeypatch):
    import os
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks not supported on this platform")
    monkeypatch.setattr(server, "_backend", None)
    monkeypatch.setattr(server, "_server_config",
                        ServerConfig(allow_write=True, project_dir=tmp_path))

    # Create a target file and a symlink pointing to it
    target = tmp_path / "target.txt"
    target.write_text("secure data\n")
    audit_path = tmp_path / "annotate_audit.jsonl"
    audit_path.symlink_to(target)

    # Calling _audit_write should NOT write to the target (or through the symlink)
    server._audit_write(_AUDIT_PREVIEW, "applied")

    # The target file must remain untouched
    assert target.read_text() == "secure data\n"


def test_audit_write_uses_private_permissions(tmp_path, monkeypatch):
    import os
    monkeypatch.setattr(server, "_backend", None)
    monkeypatch.setattr(server, "_server_config",
                        ServerConfig(allow_write=True, project_dir=tmp_path))

    server._audit_write(_AUDIT_PREVIEW, "applied")

    audit_path = tmp_path / "annotate_audit.jsonl"
    assert audit_path.exists()
    # On POSIX, check permissions are 0o600 (owner read/write only)
    if os.name == "posix":
        mode = audit_path.stat().st_mode & 0o777
        assert mode == 0o600


def test_audit_log_path_uses_config_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_backend", None)
    monkeypatch.setattr(server, "_server_config",
                        ServerConfig(allow_write=True, project_dir=tmp_path))
    assert server._audit_log_path() == Path(tmp_path) / "annotate_audit.jsonl"


# --------------------------------------------------------------------------- #
# Write-volume counter (must be per client session, not process-global)
# --------------------------------------------------------------------------- #

def test_write_attempts_are_per_session():
    server._write_attempts_by_session.clear()
    ctx_a = _FakeCtx(supports=True)
    ctx_b = _FakeCtx(supports=True)
    assert server._bump_write_attempts(ctx_a) == 1
    assert server._bump_write_attempts(ctx_a) == 2
    assert server._bump_write_attempts(ctx_b) == 1  # B's count is independent of A
    assert server._bump_write_attempts(ctx_a) == 3


def test_write_attempts_global_fallback_without_session():
    class _NoSession:
        session = None

    before = server._annotate_attempts
    assert server._bump_write_attempts(_NoSession()) == before + 1

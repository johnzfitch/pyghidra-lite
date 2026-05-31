"""Red-team simulations.

These tests take the role of the attacker: each one attempts an actual exploit
against a hardened surface and asserts the attempt fails (fails *closed*). They
are the evidence behind the security claims -- not inspection. None of them
require Ghidra/JVM; they drive the validators, middleware, and spawn paths
directly with adversarial input.

Surfaces covered:
  1. Restrict-path escape (absolute, .., symlink) and TOCTOU re-validation
  2. project_id / unit_id injection (incl. the trailing-newline regex bypass)
  3. No remote-code / network execution in bunfs extraction
  4. DNS rebinding (malicious Host header) rejection
  5. Bearer-auth bypass attempts
  6. Loopback detection fails closed for ambiguous/external hosts
  7. Background-job queue exhaustion cap
  8. Error-message path disclosure (redaction)
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from mcp.server.transport_security import TransportSecurityMiddleware

from pyghidra_lite import server
from pyghidra_lite.backend import parse_analysis_id


# ---------------------------------------------------------------------------
# 1. Restrict-path escape
# ---------------------------------------------------------------------------
class TestRestrictPathEscape:
    @pytest.fixture
    def restricted(self, tmp_path, monkeypatch):
        root = tmp_path / "allowed"
        root.mkdir()
        monkeypatch.setattr(server, "_server_config", server.ServerConfig(restrict_paths=[root]))
        return root, tmp_path

    def test_absolute_path_outside_root_blocked(self, restricted):
        with pytest.raises(ValueError):
            server._resolve_import_path("/etc/passwd")

    def test_dotdot_traversal_blocked(self, restricted):
        root, tmp = restricted
        (tmp / "secret.bin").write_bytes(b"x")
        with pytest.raises(ValueError):
            server._resolve_import_path(str(root / ".." / "secret.bin"))

    def test_symlink_into_root_pointing_outside_blocked(self, restricted):
        root, tmp = restricted
        outside = tmp / "outside.bin"
        outside.write_bytes(b"x")
        link = root / "innocent.bin"
        link.symlink_to(outside)
        with pytest.raises(ValueError):
            server._resolve_import_path(str(link))

    def test_legit_path_inside_root_allowed(self, restricted):
        root, _ = restricted
        f = root / "ok.bin"
        f.write_bytes(b"x")
        assert server._resolve_import_path(str(f)) == f.resolve()

    def test_toctou_revalidation_blocks_escape(self, restricted):
        # Simulates the swap: the path handed to import resolves outside the root.
        root, tmp = restricted
        outside = tmp / "evil.bin"
        outside.write_bytes(b"x")
        link = root / "x.bin"
        link.symlink_to(outside)
        with pytest.raises(ValueError):
            server._assert_within_restrict_roots(link)


# ---------------------------------------------------------------------------
# 2. project_id / unit_id injection
# ---------------------------------------------------------------------------
class TestIdInjection:
    @pytest.mark.parametrize("evil", [
        "../../etc",
        "..",
        "/etc/passwd",
        "abc/../def",
        "ABCDEF0123456789",            # uppercase not allowed
        "g000000000000000",            # non-hex
        "abcdef0123456789/x",          # path separator
        "abcdef0123456789\n",          # trailing newline (the $ vs \Z bypass)
        "abcdef0123456789\x00",        # null byte
        "",
        "0" * 15,                      # too short
        "0" * 17,                      # too long
    ])
    def test_invalid_project_id_rejected(self, evil):
        with pytest.raises(ValueError):
            server._validate_project_id(evil)

    def test_valid_ids_accepted(self):
        server._validate_project_id("abcdef0123456789")
        server._validate_project_id("abcdef0123456789-fast")

    def test_safe_project_path_rejects_escape(self, tmp_path):
        with pytest.raises(ValueError):
            server._safe_project_path(tmp_path, "../../etc")

    def test_parse_analysis_id_rejects_newline_in_unit_part(self):
        # endswith('-fast') is true here, but the unit part has an embedded
        # newline -- must be rejected, not parsed into a newline-bearing id.
        assert parse_analysis_id("abcdef0123456789\n-fast") is None

    def test_parse_analysis_id_accepts_clean(self):
        assert parse_analysis_id("abcdef0123456789-deep") == ("abcdef0123456789", "deep")


# ---------------------------------------------------------------------------
# 3. No remote-code / network execution in bunfs extraction
# ---------------------------------------------------------------------------
class TestNoRemoteCodeExec:
    def _wire(self, monkeypatch, tmp_path, *, extractor_present):
        binpath = tmp_path / "app.bin"
        binpath.write_bytes(b"\x00")
        monkeypatch.setattr(server, "_locked_tools",
                            lambda h, work: {"runtimes": [{"type": "bunfs"}]})
        monkeypatch.setattr(server, "_handle_analysis_id", lambda h: None)
        monkeypatch.setattr(server, "_find_on_disk", lambda a: None)
        monkeypatch.setattr(server, "_read_status_file",
                            lambda u: {"binary_path": str(binpath)})
        fake = "/usr/local/bin/bun-extract-bundled" if extractor_present else None
        monkeypatch.setattr(server.shutil, "which", lambda name: fake)
        calls: list = []

        def fake_run(argv, **kw):
            calls.append([str(a) for a in argv])

            class _R:
                returncode = 0
            return _R()

        monkeypatch.setattr(server.subprocess, "run", fake_run)
        return binpath, calls

    def test_extract_only_runs_local_pinned_tool(self, monkeypatch, tmp_path):
        _, calls = self._wire(monkeypatch, tmp_path, extractor_present=True)
        server._extract_bunfs_blocking(MagicMock(), tmp_path / "out")

        assert len(calls) == 1, "exactly one spawn expected"
        argv = calls[0]
        # Only the locally-resolved pinned extractor, fixed argv -- never a
        # package launcher and never the `x` (fetch+run) subcommand.
        assert Path(argv[0]).name == "bun-extract-bundled"
        names = {Path(a).name for a in argv}
        assert not (names & {"bun", "npm", "npx", "yarn", "pnpm", "curl", "wget", "sh", "bash"})
        assert "x" not in argv[1:2], "must not invoke the network `x` subcommand"

    def test_extract_without_tool_does_not_spawn_or_fetch(self, monkeypatch, tmp_path):
        _, calls = self._wire(monkeypatch, tmp_path, extractor_present=False)
        with pytest.raises(RuntimeError, match="bunfs extraction unavailable"):
            server._extract_bunfs_blocking(MagicMock(), tmp_path / "out")
        assert calls == [], "no subprocess (and thus no network fetch) when tool absent"


# ---------------------------------------------------------------------------
# 4. DNS rebinding
# ---------------------------------------------------------------------------
class TestDnsRebinding:
    def _mw(self, host="127.0.0.1", port=8000, extra=()):
        return TransportSecurityMiddleware(settings=server._build_transport_security(host, port, extra))

    @pytest.mark.parametrize("evil", [
        "attacker.com:8000",
        "evil.com",
        "127.0.0.1.attacker.com:8000",
        "localhost.attacker.com:8000",
        "169.254.169.254:8000",          # cloud metadata endpoint
    ])
    def test_malicious_host_header_rejected(self, evil):
        assert self._mw()._validate_host(evil) is False

    @pytest.mark.parametrize("ok", ["localhost:8000", "127.0.0.1:8000", "[::1]:8000"])
    def test_legitimate_localhost_allowed(self, ok):
        assert self._mw()._validate_host(ok) is True

    def test_explicitly_allowed_host_passes_others_fail(self):
        mw = self._mw("0.0.0.0", 8000, ("proxy.internal:8000",))
        assert mw._validate_host("proxy.internal:8000") is True
        assert mw._validate_host("attacker.com:8000") is False


# ---------------------------------------------------------------------------
# 5. Bearer-auth bypass
# ---------------------------------------------------------------------------
class TestAuthBypass:
    def _status_for(self, headers, token="s3cret"):
        sent: list = []

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        async def app(scope, r, s):
            await s({"type": "http.response.start", "status": 200, "headers": []})

        mw = server._BearerAuthMiddleware(app, token)
        asyncio.run(mw({"type": "http", "headers": headers}, recv, send))
        return sent[0]["status"]

    @pytest.mark.parametrize("headers", [
        [],
        [(b"authorization", b"")],
        [(b"authorization", b"Bearer")],
        [(b"authorization", b"Bearer wrong")],
        [(b"authorization", b"bearer s3cret")],     # wrong case
        [(b"authorization", b"Basic s3cret")],       # wrong scheme
        [(b"authorization", b"Bearer s3cret ")],     # trailing space
        [(b"authorization", b" Bearer s3cret")],     # leading space
        [(b"x-api-key", b"s3cret")],                 # wrong header
        [(b"authorization", b"Bearer s3cretEXTRA")], # prefix-not-equal
    ])
    def test_bypass_attempts_get_401(self, headers):
        assert self._status_for(headers) == 401

    def test_correct_token_passes(self):
        assert self._status_for([(b"authorization", b"Bearer s3cret")]) == 200

    def test_non_http_scope_is_not_gated(self):
        called = {"v": False}

        async def recv():
            return {}

        async def send(message):
            pass

        async def app(scope, r, s):
            called["v"] = True

        mw = server._BearerAuthMiddleware(app, "s3cret")
        asyncio.run(mw({"type": "lifespan"}, recv, send))
        assert called["v"] is True


# ---------------------------------------------------------------------------
# 6. Loopback detection fails closed
# ---------------------------------------------------------------------------
class TestLoopbackFailClosed:
    @pytest.mark.parametrize("host", [
        "0.0.0.0",
        "::",
        "10.0.0.5",
        "example.com",
        "127.1",              # abbreviated form not parsed -> treat as non-loopback
        "0x7f000001",         # hex evasion -> not parsed -> non-loopback
        "localhost.",         # trailing dot -> not the literal "localhost"
        "127.0.0.1.evil.com",
    ])
    def test_ambiguous_or_external_not_treated_as_loopback(self, host):
        # Anything not provably loopback must be False so the CLI then *requires*
        # --auth-token: fail closed, never fail open into an unauthenticated bind.
        assert server._is_loopback_host(host) is False

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2"])
    def test_genuine_loopback_recognized(self, host):
        assert server._is_loopback_host(host) is True


# ---------------------------------------------------------------------------
# 7. Background-job queue exhaustion
# ---------------------------------------------------------------------------
class TestJobQueueExhaustion:
    def test_flooding_active_jobs_is_capped(self, monkeypatch):
        flood = {f"{i:016x}": {"status": "running"} for i in range(server._MAX_QUEUED_JOBS)}
        monkeypatch.setattr(server, "_active_jobs", flood)
        with pytest.raises(ValueError, match="queue full"):
            server._reject_if_jobs_full()

    def test_terminal_jobs_do_not_count(self, monkeypatch):
        done = {f"{i:016x}": {"status": "complete"} for i in range(server._MAX_QUEUED_JOBS)}
        monkeypatch.setattr(server, "_active_jobs", done)
        server._reject_if_jobs_full()  # must not raise


# ---------------------------------------------------------------------------
# 8. Error-message path disclosure
# ---------------------------------------------------------------------------
class TestErrorRedaction:
    def test_home_directory_redacted(self, monkeypatch):
        monkeypatch.setattr(server, "_server_config", server.ServerConfig())
        leak = str(Path.home() / ".ssh" / "id_rsa")
        out = server._sanitize_error_text(f"cannot read {leak}")
        assert str(Path.home()) not in out

    def test_runtime_home_redacted(self, tmp_path, monkeypatch):
        rh = tmp_path / "runtime"
        monkeypatch.setattr(server, "_server_config", server.ServerConfig(runtime_home=rh))
        out = server._sanitize_error_text(f"jvm crash dump at {rh}/hs_err.log")
        assert str(rh) not in out
        assert "<runtime-home>" in out

    def test_guarded_tool_call_redacts_unexpected_exception(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "_server_config",
                            server.ServerConfig(project_dir=tmp_path / "proj"))
        leak = str((tmp_path / "proj" / "abcdef0123456789").resolve())

        def op():
            raise KeyError(leak)

        with pytest.raises(RuntimeError) as exc:
            server._guarded_tool_call("decompile", op)
        assert leak not in str(exc.value)
        assert "<project-dir>" in str(exc.value)


# ---------------------------------------------------------------------------
# 9. DNS rebinding -- END TO END through the real running ASGI pipeline
# ---------------------------------------------------------------------------
# Unlike TestDnsRebinding (which calls the validator helper), this drives the
# actual streamable-HTTP app with the session task group running, the same way
# `pyghidra-lite serve -t streamable-http` does. It would FAIL if the protection
# were configured but never wired into the request pipeline.
class TestDnsRebindingEndToEnd:
    def _drive(self, host: str) -> list:
        import anyio

        server.mcp.settings.host = "127.0.0.1"
        server.mcp.settings.port = 8000
        server.mcp.settings.transport_security = server._build_transport_security("127.0.0.1", 8000)
        app = server.mcp.streamable_http_app()
        path = server.mcp.settings.streamable_http_path
        body = (b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":'
                b'"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}')
        statuses: list = []

        async def run():
            scope = {
                "type": "http", "http_version": "1.1", "method": "POST", "path": path,
                "raw_path": path.encode(), "query_string": b"", "scheme": "http",
                "server": ("127.0.0.1", 8000), "client": ("203.0.113.9", 51000),
                "headers": [(b"host", host.encode()), (b"content-type", b"application/json"),
                            (b"accept", b"application/json, text/event-stream"),
                            (b"content-length", str(len(body)).encode())],
            }

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(m):
                if m["type"] == "http.response.start":
                    statuses.append(m["status"])

            async with server.mcp.session_manager.run():
                with anyio.move_on_after(20):
                    await app(scope, receive, send)

        anyio.run(run)
        return statuses

    def test_forged_host_rejected_end_to_end(self):
        statuses = self._drive("attacker.com:8000")
        assert statuses and statuses[0] == 421, f"expected 421, got {statuses}"


# ---------------------------------------------------------------------------
# 10. Live trojan-on-PATH trap: prove no package launcher is ever executed
# ---------------------------------------------------------------------------
# This plants REAL executables named bun/npm/npx/node/sh on PATH that write a
# marker if run, then triggers the extraction path. The pinned extractor is the
# only thing permitted to run; if any launcher fired (i.e. a `bun x`-style fetch
# survived), the marker would appear. This executes real processes, not mocks.
class TestNoLauncherExecLive:
    def test_extraction_never_runs_a_package_launcher(self, tmp_path, monkeypatch):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        marker = tmp_path / "LAUNCHER_RAN"
        for name in ("bun", "npm", "npx", "node", "sh", "bash", "curl", "wget"):
            p = bindir / name
            p.write_text(f'#!/bin/sh\necho "$0 $@" >> "{marker}"\n')
            p.chmod(0o755)
        # The one thing we DO permit: a locally pre-installed pinned extractor.
        ext = bindir / "bun-extract-bundled"
        ext.write_text('#!/bin/sh\nexit 0\n')
        ext.chmod(0o755)
        monkeypatch.setenv("PATH", str(bindir))  # nothing but our planted bins

        binpath = tmp_path / "app.bin"
        binpath.write_bytes(b"\x00")
        monkeypatch.setattr(server, "_locked_tools", lambda h, w: {"runtimes": [{"type": "bunfs"}]})
        monkeypatch.setattr(server, "_handle_analysis_id", lambda h: None)
        monkeypatch.setattr(server, "_find_on_disk", lambda a: None)
        monkeypatch.setattr(server, "_read_status_file", lambda u: {"binary_path": str(binpath)})

        server._extract_bunfs_blocking(MagicMock(), tmp_path / "out")

        assert not marker.exists(), (
            f"a package launcher was executed: {marker.read_text() if marker.exists() else ''}"
        )


# ---------------------------------------------------------------------------
# 11. Import worker spawns only our own interpreter (fixed self-spawn)
# ---------------------------------------------------------------------------
class TestWorkerSelfSpawn:
    def test_worker_argv_is_fixed_self_import(self, tmp_path, monkeypatch):
        import sys

        monkeypatch.setattr(server, "_server_config",
                            server.ServerConfig(project_dir=tmp_path))
        monkeypatch.setattr(server, "_worker_semaphore", asyncio.Semaphore(1))
        captured: dict = {}

        class _Proc:
            pid = 4242

            async def communicate(self):
                return (b"", b"")
            returncode = 0

        async def fake_exec(*argv, **kw):
            captured["argv"] = list(argv)
            return _Proc()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        binpath = tmp_path / "app.bin"
        binpath.write_bytes(b"\x00")

        job = {"status": "queued"}
        asyncio.run(server._run_worker(binpath, "abcdef0123456789-fast", "fast", job))

        argv = captured["argv"]
        # The agent controls only the binary path (data); the program is always us.
        assert argv[0] == sys.executable
        assert argv[1:5] == ["-m", "pyghidra_lite.server", "import", str(binpath)]


# ---------------------------------------------------------------------------
# 12. Top-to-bottom holder impenetrability (the big picture)
# ---------------------------------------------------------------------------
# These don't probe one validator -- they assert that, once the server is LIVE
# (go_live, the state during a real connection), the module's security *holders*
# cannot be tampered with through any reachable in-process surface. This is the
# allowlist contract: the only permitted config transition is the one-time build
# at boot; everything after is denied by construction.
@pytest.fixture
def served():
    """Put the module in its live/sealed state; restore on teardown.

    go_live() flips global module state, so teardown MUST reset it or every
    later test that calls configure_server would raise ConfigLockedError.
    """
    was_live = server.is_config_live()
    server.go_live()
    try:
        yield
    finally:
        server._config_live = was_live


class TestConfigHolderImpenetrable:
    def test_configure_server_denied_after_go_live(self, served, tmp_path):
        with pytest.raises(server.ConfigLockedError):
            server.configure_server(restrict_paths=[tmp_path])

    def test_config_fields_are_frozen(self):
        cfg = server.get_config()
        import dataclasses
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.shared = True
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.runtime_home = None
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.restrict_paths = ()

    def test_restrict_paths_is_an_immutable_tuple(self):
        rp = server.get_config().restrict_paths
        assert isinstance(rp, tuple)
        assert not hasattr(rp, "append")

    def test_restrict_paths_coerces_any_iterable_to_tuple(self):
        # Even when built from a list, the stored value is an immutable tuple.
        cfg = server.ServerConfig(restrict_paths=[Path("/a"), Path("/b")])
        assert isinstance(cfg.restrict_paths, tuple)

    def test_get_config_is_a_stable_single_read_path(self):
        assert server.get_config() is server.get_config()

    def test_go_live_is_idempotent(self, served):
        server.go_live()
        assert server.is_config_live() is True


class TestTransportHolderImpenetrable:
    def test_dns_protection_is_on_when_built(self):
        ts = server._build_transport_security("127.0.0.1", 8000)
        assert ts is not None
        assert ts.enable_dns_rebinding_protection is True

    def test_forged_host_rejected_end_to_end_while_live(self, served):
        # Drive the real pipeline (like TestDnsRebindingEndToEnd) while the module
        # is in its live state: forged Host must still be 421.
        import anyio

        server.mcp.settings.transport_security = server._build_transport_security("127.0.0.1", 8000)
        # The session manager is cached on the mcp singleton and .run() is
        # one-shot; reset so this test gets a fresh instance.
        server.mcp._session_manager = None
        app = server.mcp.streamable_http_app()
        path = server.mcp.settings.streamable_http_path
        body = (b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":'
                b'"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}')
        statuses: list = []

        async def run():
            scope = {
                "type": "http", "http_version": "1.1", "method": "POST", "path": path,
                "raw_path": path.encode(), "query_string": b"", "scheme": "http",
                "server": ("127.0.0.1", 8000), "client": ("203.0.113.9", 51000),
                "headers": [(b"host", b"attacker.com:8000"), (b"content-type", b"application/json"),
                            (b"accept", b"application/json, text/event-stream"),
                            (b"content-length", str(len(body)).encode())],
            }

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(m):
                if m["type"] == "http.response.start":
                    statuses.append(m["status"])

            async with server.mcp.session_manager.run():
                with anyio.move_on_after(20):
                    await app(scope, receive, send)

        anyio.run(run)
        assert statuses and statuses[0] == 421


class TestNoToolCanReachSettings:
    """Adversarial tripwire: no MCP tool may carry a settings-mutation surface.

    If a future tool quietly adds a way to call configure_server / go_live, write
    _server_config, or rewrite mcp.settings, this fails -- so the immutability
    contract can't be silently regressed. (Reading via get_config() is allowed.)
    """
    FORBIDDEN = ("configure_server(", "go_live(", "_server_config =",
                 "_server_config=", "mcp.settings.", "object.__setattr__(",
                 "_config_live")

    def test_registered_tools_have_no_config_writers(self):
        import inspect
        tools = server.mcp._tool_manager.list_tools()
        assert len(tools) >= 8
        offenders = {}
        for tool in tools:
            src = inspect.getsource(tool.fn)
            hits = [tok for tok in self.FORBIDDEN if tok in src]
            if hits:
                offenders[tool.name] = hits
        assert not offenders, f"tool(s) carry a settings-mutation surface: {offenders}"

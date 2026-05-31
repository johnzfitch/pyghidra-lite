"""True end-to-end security tests against a REAL running server.

Unlike tests/test_red_team.py (in-process), these spawn an actual
`pyghidra-lite serve` subprocess and attack it over real TCP sockets -- the only
faithful test of the deployed security posture. They require a JVM + Ghidra and
so are skipped unless PYGHIDRA_E2E=1 (set in the dedicated CI job); they never
run in the JVM-less dev container or on a normal `pytest` invocation.

Run locally on a host with JDK 21 + Ghidra:
    PYGHIDRA_E2E=1 GHIDRA_INSTALL_DIR=/opt/ghidra uv run pytest tests/test_security_e2e.py -v
"""

import os
import socket
import subprocess
import sys
import time

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("PYGHIDRA_E2E"),
    reason="real-server E2E; needs JDK+Ghidra. Set PYGHIDRA_E2E=1 to run.",
)

TOKEN = "e2e-secret-token"
BOOT_TIMEOUT = 240  # JVM + Ghidra startup can be slow in CI


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server_url(tmp_path_factory):
    port = _free_port()
    restrict = tmp_path_factory.mktemp("restrict")
    proc = subprocess.Popen(
        [sys.executable, "-m", "pyghidra_lite.server", "serve",
         "--transport", "streamable-http", "--host", "127.0.0.1",
         "--port", str(port), "--auth-token", TOKEN,
         "--restrict-path", str(restrict)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    url = f"http://127.0.0.1:{port}/mcp"
    deadline = time.time() + BOOT_TIMEOUT
    try:
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"server exited early:\n{proc.stdout.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError("server did not start within timeout")
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _post(url, host=None, auth=None):
    headers = {"content-type": "application/json",
               "accept": "application/json, text/event-stream"}
    if host:
        headers["host"] = host
    if auth is not None:
        headers["authorization"] = auth
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "attacker", "version": "0"}}}
    return httpx.post(url, json=body, headers=headers, timeout=10)


def test_missing_token_rejected(server_url):
    assert _post(server_url).status_code == 401


def test_wrong_token_rejected(server_url):
    assert _post(server_url, auth="Bearer nope").status_code == 401


def test_forged_host_rejected(server_url):
    # Valid token, but a DNS-rebinding Host header -> must be blocked.
    assert _post(server_url, host="attacker.com", auth=f"Bearer {TOKEN}").status_code == 421


def test_legit_request_passes_both_guards(server_url):
    # Correct token + loopback Host: must get past auth AND host validation
    # (whatever the MCP layer then returns, it must not be a 401/421 block).
    r = _post(server_url, auth=f"Bearer {TOKEN}")
    assert r.status_code not in (401, 421)


def test_forged_host_stays_blocked_on_repeat(server_url):
    # The allowed-host set is fixed at boot; it cannot be widened at runtime, so
    # a forged Host is rejected every time, not just the first.
    for _ in range(3):
        assert _post(server_url, host="evil.example", auth=f"Bearer {TOKEN}").status_code == 421

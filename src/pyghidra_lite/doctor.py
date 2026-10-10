"""`pyghidra-lite doctor`: read-only environment diagnosis.

Checks everything the server needs before it can analyze anything -- Python
packages, Ghidra install and version, a JDK inside Ghidra's declared range,
the native decompiler for this host, a project dir Ghidra accepts, project
locks, and the shared backend. Nothing here starts the JVM or writes files.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from importlib import metadata
from pathlib import Path

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str | None = None


def _read_properties(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    try:
        text = path.read_text(encoding="latin-1")
    except OSError:
        return props
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key.strip()] = value.strip()
    return props


def _pkg_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def decompiler_platform() -> str | None:
    """Ghidra's os/<platform> directory name for this host, or None if unsupported."""
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm_64", "aarch64": "arm_64"}.get(machine)
    if arch is None:
        return None
    if sys.platform == "win32":
        prefix = "win"
    elif sys.platform == "darwin":
        prefix = "mac"
    elif sys.platform.startswith("linux"):
        prefix = "linux"
    else:
        return None
    return f"{prefix}_{arch}"


def parse_java_major(version_output: str) -> int | None:
    """Major version from `java -version` output ('1.8.0_x' -> 8, '21.0.11' -> 21)."""
    m = re.search(r'version "(\d+)(?:\.(\d+))?', version_output)
    if not m:
        return None
    major = int(m.group(1))
    if major == 1 and m.group(2):
        major = int(m.group(2))
    return major


def _find_java() -> tuple[Path | None, str]:
    if java_home := os.environ.get("JAVA_HOME"):
        for name in ("java.exe", "java"):
            exe = Path(java_home) / "bin" / name
            if exe.is_file():
                return exe, "JAVA_HOME"
    if found := shutil.which("java"):
        return Path(found), "PATH"
    return None, ""


def check_python() -> Check:
    v = sys.version_info
    if v < (3, 11):
        return Check("python", FAIL, f"{platform.python_version()} (need >= 3.11)",
                     "Install Python 3.11 or newer.")
    return Check("python", OK, f"{platform.python_version()} ({sys.executable})")


def check_packages() -> list[Check]:
    checks = []
    mcp_v = _pkg_version("mcp")
    if mcp_v is None:
        checks.append(Check("mcp", FAIL, "not installed", "pip install 'mcp>=1.21,<2'"))
    elif mcp_v.split(".", 1)[0] != "1":
        checks.append(Check("mcp", FAIL, f"{mcp_v} (2.x removed mcp.server.fastmcp)",
                            "pip install 'mcp>=1.21,<2'"))
    else:
        checks.append(Check("mcp", OK, mcp_v))
    for name in ("pyghidra", "jpype1"):
        v = _pkg_version(name)
        checks.append(Check(name, OK, v) if v else
                      Check(name, FAIL, "not installed", f"pip install {name}"))
    return checks


def check_ghidra(ghidra_dir: Path | None) -> tuple[Check, Path | None, dict[str, str]]:
    from pyghidra_lite.backend import find_ghidra_install

    if ghidra_dir:
        source = "--ghidra-dir"
    elif os.environ.get("GHIDRA_INSTALL_DIR"):
        source = "GHIDRA_INSTALL_DIR"
    else:
        source = "auto-detected"
    install = find_ghidra_install(ghidra_dir)
    if install is None:
        given = ghidra_dir or os.environ.get("GHIDRA_INSTALL_DIR")
        detail = (f"{given} has no Ghidra/application.properties" if given
                  else "not found in /opt/ghidra, ~/ghidra, Homebrew or /usr paths")
        return (Check("ghidra", FAIL, detail,
                      "Set GHIDRA_INSTALL_DIR (or --ghidra-dir) to the extracted ghidra_<ver>_PUBLIC dir."),
                None, {})
    props = _read_properties(install / "Ghidra" / "application.properties")
    version = props.get("application.version", "unknown")
    major = version.split(".", 1)[0]
    status = OK if major.isdigit() and int(major) >= 11 else WARN
    detail = f"{version} at {install} ({source})"
    fix = None if status == OK else "pyghidra-lite is tested with Ghidra 11.x and 12.x."
    return Check("ghidra", status, detail, fix), install, props


def check_java(props: dict[str, str]) -> list[Check]:
    exe, source = _find_java()
    if exe is None:
        return [Check("java", FAIL, "no java on JAVA_HOME or PATH",
                      "Install a 64-bit JDK 21+ and set JAVA_HOME.")]
    try:
        out = subprocess.run([str(exe), "-version"], capture_output=True, text=True, timeout=20)
        text = out.stderr + out.stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        return [Check("java", FAIL, f"{exe} did not run: {e}", "Check the JDK installation.")]
    major = parse_java_major(text)
    first = text.strip().splitlines()[0] if text.strip() else "?"
    lo = props.get("application.java.min", "")
    hi = props.get("application.java.max", "")
    checks = []
    if major is None:
        checks.append(Check("java", WARN, f"{exe}: unrecognized version output: {first}"))
    elif (lo.isdigit() and major < int(lo)) or (hi.isdigit() and major > int(hi)):
        want = f"{lo}..{hi}" if hi else f">= {lo}"
        checks.append(Check("java", FAIL, f"Java {major} at {exe} ({source}); this Ghidra needs {want}",
                            f"Install JDK {lo} and point JAVA_HOME at it."))
    else:
        bits = "" if "64-Bit" in text or "64-bit" in text else " (could not confirm 64-bit)"
        checks.append(Check("java", OK if not bits else WARN, f"Java {major} at {exe} ({source}){bits}"))
    javac = exe.with_name("javac.exe" if exe.suffix == ".exe" else "javac")
    if not javac.exists():
        checks.append(Check("jdk", WARN, f"no javac next to {exe}: this looks like a JRE",
                            "Ghidra requires a full JDK; install one and set JAVA_HOME."))
    return checks


def check_decompiler(install: Path | None) -> Check:
    plat = decompiler_platform()
    if plat is None:
        return Check("decompiler", FAIL, f"unsupported host {sys.platform}/{platform.machine()}")
    if install is None:
        return Check("decompiler", INFO, f"skipped (no Ghidra); host platform {plat}")
    name = "decompile.exe" if plat.startswith("win") else "decompile"
    for base in (install / "Ghidra" / "Features" / "Decompiler" / "os" / plat,
                 install / "Ghidra" / "Features" / "Decompiler" / "build" / "os" / plat):
        if (base / name).is_file():
            return Check("decompiler", OK, str(base / name))
    return Check("decompiler", FAIL, f"no native decompiler for {plat} in this Ghidra",
                 "Use an official Ghidra release that ships this platform, or build it "
                 "(Ghidra/Features/Decompiler: gradle buildNatives).")


def check_project_dir(project_dir: Path | None, ghidra_major: int | None) -> tuple[Check, Path]:
    from pyghidra_lite.backend import DEFAULT_PROJECT_DIR, LEGACY_PROJECT_DIR

    if project_dir:
        source = "--project-dir"
    elif os.environ.get("PYGHIDRA_LITE_PROJECT_DIR"):
        project_dir, source = Path(os.environ["PYGHIDRA_LITE_PROJECT_DIR"]), "PYGHIDRA_LITE_PROJECT_DIR"
    else:
        project_dir = DEFAULT_PROJECT_DIR
        source = "legacy default" if DEFAULT_PROJECT_DIR == LEGACY_PROJECT_DIR else "default"
    resolved = Path(project_dir).expanduser().absolute()
    dotted = [p for p in resolved.parts if p.startswith(".")]
    if dotted and ghidra_major is not None and ghidra_major >= 12:
        return (Check("project_dir", FAIL,
                      f"{resolved} ({source}) has dot-leading component(s) {', '.join(dotted)}; "
                      f"Ghidra {ghidra_major} rejects it",
                      "Set PYGHIDRA_LITE_PROJECT_DIR to a path without dot-leading components, "
                      "e.g. ~/pyghidra-lite/projects (move the old projects there to keep them)."),
                resolved)
    probe = resolved
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    if not os.access(probe, os.W_OK):
        return (Check("project_dir", FAIL, f"{resolved} ({source}) is not writable (checked {probe})",
                      "Choose a writable --project-dir."), resolved)
    state = "exists" if resolved.is_dir() else "will be created"
    return Check("project_dir", OK, f"{resolved} ({source}, {state})"), resolved


def check_locks(projects_dir: Path) -> Check:
    from pyghidra_lite.project_locks import is_project_lock_held

    live, stale = [], []
    seen: set[Path] = set()
    for pattern in ("*/*.lock", "*/*.lock~", "session-*/*/*.lock", "session-*/*/*.lock~"):
        try:
            candidates = list(projects_dir.glob(pattern))
        except OSError:
            continue
        for f in candidates:
            key = (f.name[:-1] if f.name.endswith("~") else f.name)[: -len(".lock")]
            proj = f.parent
            if proj.name != key or proj in seen:
                continue
            seen.add(proj)
            try:
                (live if is_project_lock_held(proj, key) else stale).append(proj.name)
            except OSError:
                live.append(proj.name)
    if not live and not stale:
        return Check("locks", OK, "no project locks")
    parts = []
    if live:
        parts.append(f"{len(live)} held by a live process ({', '.join(live[:5])}"
                     f"{', ...' if len(live) > 5 else ''})")
    if stale:
        parts.append(f"{len(stale)} stale (removed automatically at next server start)")
    return Check("locks", INFO, "; ".join(parts))


def check_backend(port: int) -> Check:
    import logging

    # Importing proxy logs its SDK-patch notice; not relevant to a diagnosis.
    proxy_logger = logging.getLogger("pyghidra-lite-proxy")
    level = proxy_logger.level
    proxy_logger.setLevel(logging.WARNING)
    try:
        from pyghidra_lite.proxy import DEFAULT_HOST, _is_backend_alive
    finally:
        proxy_logger.setLevel(level)

    if _is_backend_alive(DEFAULT_HOST, port):
        return Check("backend", INFO, f"shared backend running on {DEFAULT_HOST}:{port}")
    return Check("backend", INFO, f"no shared backend on {DEFAULT_HOST}:{port} (the proxy starts one on demand)")


def run_checks(ghidra_dir: Path | None = None, project_dir: Path | None = None,
               port: int = 19101) -> list[Check]:
    checks = [check_python(), *check_packages()]
    if any(c.status == FAIL and c.name in ("pyghidra", "jpype1") for c in checks):
        return checks  # backend imports pyghidra; nothing below can run
    ghidra, install, props = check_ghidra(ghidra_dir)
    checks.append(ghidra)
    if install is not None:
        checks.extend(check_java(props))
    checks.append(check_decompiler(install))
    version = props.get("application.version", "")
    major = int(version.split(".", 1)[0]) if version.split(".", 1)[0].isdigit() else None
    pd_check, resolved = check_project_dir(project_dir, major)
    checks.append(pd_check)
    if resolved.is_dir():
        checks.append(check_locks(resolved))
    checks.append(check_backend(port))
    return checks


def as_dicts(checks: list[Check]) -> list[dict]:
    return [{k: v for k, v in asdict(c).items() if v is not None} for c in checks]


def format_text(checks: list[Check]) -> str:
    tag = {OK: " ok ", WARN: "WARN", FAIL: "FAIL", INFO: "info"}
    lines = []
    for c in checks:
        lines.append(f"[{tag[c.status]}] {c.name:<12} {c.detail}")
        if c.fix and c.status in (WARN, FAIL):
            lines.append(f"{'':19}fix: {c.fix}")
    fails = sum(c.status == FAIL for c in checks)
    warns = sum(c.status == WARN for c in checks)
    lines.append("")
    lines.append("Ready." if not fails else f"{fails} problem(s) will stop analysis.")
    if warns:
        lines[-1] += f" {warns} warning(s)."
    return "\n".join(lines)

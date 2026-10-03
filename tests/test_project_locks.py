"""Cross-process Ghidra project lock handling.

The live-lock cases use a real JVM in a separate process that takes the same
FileChannel.tryLock() on <name>.lock~ that Ghidra's ChannelLocker takes, so the
probe is checked against the exact OS lock other servers and headless Ghidra
scripts hold.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pyghidra_lite.project_locks import (
    ProjectLockedError,
    clear_stale_lock,
    is_project_lock_held,
    lock_files,
    read_lock_info,
    sweep_stale_locks,
)

GHIDRA_CHANNEL_LOCK = (
    "#Ghidra Lock File\n"
    "#Sat Jun 27 16:32:21 PDT 2026\n"
    "<META>\\ Supports\\ File\\ Channel\\ Locking=Channel Lock\n"
    "Hostname=winzack\n"
    "OS\\ Architecture=amd64\n"
    "Username=tester\n"
    "Timestamp=6/27/26, 4\\:32 PM\n"
)

HOLDER_JAVA = r"""
import java.io.*;
import java.nio.channels.*;
public class Hold {
    public static void main(String[] a) throws Exception {
        FileOutputStream out = new FileOutputStream(new File(a[0]), true);
        FileLock lock = out.getChannel().tryLock();
        System.out.println(lock != null ? "LOCKED" : "BUSY");
        System.out.flush();
        System.in.read();  // hold until the test closes stdin
        if (lock != null) lock.release();
        out.close();
    }
}
"""


def _java() -> str | None:
    candidates = []
    if os.environ.get("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]) / "bin" / "java")
    candidates.append(Path.home() / "Projects" / "D4-RE" / "tools" / "jdk-21.0.11+10" / "bin" / "java")
    for c in candidates:
        for exe in (c, c.with_suffix(".exe")):
            if exe.exists():
                return str(exe)
    return shutil.which("java")


JAVA = _java()
needs_java = pytest.mark.skipif(JAVA is None, reason="no JDK available to hold a FileChannel lock")


def _make_project(tmp_path: Path, key: str = "abc-default") -> Path:
    proj = tmp_path / key
    proj.mkdir()
    (proj / f"{key}.gpr").write_text("")
    return proj


class JavaLockHolder:
    """A separate JVM holding Ghidra's channel lock on <key>.lock~."""

    def __init__(self, tmp_path: Path, hold_file: Path):
        src = tmp_path / "Hold.java"
        src.write_text(HOLDER_JAVA)
        self.proc = subprocess.Popen(
            [JAVA, str(src), str(hold_file)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        line = self.proc.stdout.readline().strip()
        if line != "LOCKED":
            self.release()
            raise RuntimeError(f"Java holder did not lock: {line!r} {self.proc.stderr.read()}")

    def release(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        self.proc.wait(timeout=30)


@pytest.fixture
def held_project(tmp_path):
    proj = _make_project(tmp_path)
    lock, hold = lock_files(proj, "abc-default")
    lock.write_text(GHIDRA_CHANNEL_LOCK)
    holder = JavaLockHolder(tmp_path, hold)
    yield proj
    holder.release()


def test_no_lock_file_is_not_held(tmp_path):
    proj = _make_project(tmp_path)
    assert is_project_lock_held(proj, "abc-default") is False


def test_lock_left_by_dead_process_is_stale_and_removed(tmp_path):
    proj = _make_project(tmp_path)
    lock, hold = lock_files(proj, "abc-default")
    lock.write_text(GHIDRA_CHANNEL_LOCK)
    hold.write_bytes(b"")
    assert is_project_lock_held(proj, "abc-default") is False
    assert clear_stale_lock(proj, "abc-default") is True
    assert not lock.exists() and not hold.exists()


def test_file_lock_without_channel_support_is_treated_as_held(tmp_path):
    """A plain 'File Lock' carries no liveness signal, so it is never deleted."""
    proj = _make_project(tmp_path)
    lock, _ = lock_files(proj, "abc-default")
    lock.write_text(GHIDRA_CHANNEL_LOCK.replace("=Channel Lock", "=File Lock"))
    assert is_project_lock_held(proj, "abc-default") is True
    assert clear_stale_lock(proj, "abc-default") is False
    assert lock.exists()


def test_read_lock_info_parses_ghidra_properties(tmp_path):
    proj = _make_project(tmp_path)
    lock, _ = lock_files(proj, "abc-default")
    lock.write_text(GHIDRA_CHANNEL_LOCK)
    info = read_lock_info(lock)
    assert info["<META> Supports File Channel Locking"] == "Channel Lock"
    assert info["Hostname"] == "winzack"
    assert info["Timestamp"] == "6/27/26, 4:32 PM"


def test_read_lock_info_decodes_unicode_escapes(tmp_path):
    """Java 21 writes the narrow no-break space in timestamps as \\u202F."""
    proj = _make_project(tmp_path)
    lock, _ = lock_files(proj, "abc-default")
    lock.write_text("Timestamp=10/2/26, 9\\:40\\u202FPM\n")
    assert read_lock_info(lock)["Timestamp"] == "10/2/26, 9:40 PM"


@needs_java
def test_lock_held_by_live_jvm_is_reported_held(held_project):
    assert is_project_lock_held(held_project, "abc-default") is True


@needs_java
def test_clear_stale_lock_leaves_live_lock_in_place(held_project):
    lock, hold = lock_files(held_project, "abc-default")
    assert clear_stale_lock(held_project, "abc-default") is False
    assert lock.exists() and hold.exists()


@needs_java
def test_startup_sweep_survives_live_lock_and_removes_only_stale(tmp_path, held_project):
    """The old sweep unlinked every *.lock~; on Windows a held one raised
    WinError 32 and killed server startup."""
    stale = _make_project(tmp_path, "def-fast")
    s_lock, s_hold = lock_files(stale, "def-fast")
    s_lock.write_text(GHIDRA_CHANNEL_LOCK)
    s_hold.write_bytes(b"")
    session_dir = tmp_path / "session-1234abcd"
    session_dir.mkdir()
    session_stale = _make_project(session_dir, "ghi-default")
    ss_lock, _ = lock_files(session_stale, "ghi-default")
    ss_lock.write_text(GHIDRA_CHANNEL_LOCK)

    result = sweep_stale_locks(tmp_path)

    assert str(held_project) in result["live"]
    assert set(result["removed"]) == {str(stale), str(session_stale)}
    assert lock_files(held_project, "abc-default")[0].exists()
    assert not s_lock.exists() and not s_hold.exists() and not ss_lock.exists()


@needs_java
def test_lock_becomes_stale_when_holder_exits(tmp_path):
    proj = _make_project(tmp_path)
    lock, hold = lock_files(proj, "abc-default")
    lock.write_text(GHIDRA_CHANNEL_LOCK)
    holder = JavaLockHolder(tmp_path, hold)
    assert is_project_lock_held(proj, "abc-default") is True
    holder.release()
    assert is_project_lock_held(proj, "abc-default") is False
    assert clear_stale_lock(proj, "abc-default") is True


def test_project_locked_error_names_holder(tmp_path):
    err = ProjectLockedError(tmp_path, "abc-default", {"Hostname": "winzack", "Username": "tester"})
    assert "abc-default" in str(err)
    assert "Hostname=winzack" in str(err)
    assert "not removed" in str(err)

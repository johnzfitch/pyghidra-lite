"""Cross-process Ghidra project lock inspection.

Several pyghidra-lite servers (one per MCP client) and external headless Ghidra
scripts may share one project directory. Ghidra guards each project with
``<name>.lock`` (a properties file) plus, on filesystems that support it, an
OS-level FileChannel lock held on ``<name>.lock~`` for as long as the owning
JVM keeps the project open (see generic.util.ChannelLocker / FileChannelLock).

The ``.lock`` file alone says nothing about liveness: it survives crashes. The
``.lock~`` channel lock does -- the OS drops it when the owning process exits.
Ghidra itself decides staleness by trying to take that channel lock; this
module performs the same probe from Python so the server never deletes, or
crashes on, a lock that a live process still holds.

  * Windows: a held ``.lock~`` cannot be deleted (WinError 32) and its byte
    range cannot be locked (msvcrt.locking raises).
  * POSIX: Java's FileChannel.tryLock is an fcntl record lock, so
    fcntl.lockf(LOCK_EX | LOCK_NB) conflicts with it. Record locks never
    conflict within one process, so callers must not use this to probe
    projects their own JVM has open (they already know those).
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

CHANNEL_LOCK_TYPE = "Channel Lock"
_LOCK_TYPE_KEY = "<META> Supports File Channel Locking"


class ProjectLockedError(RuntimeError):
    """A Ghidra project is locked by another live process."""

    def __init__(self, project_path: Path, project_key: str, holder: dict[str, str] | None = None):
        self.project_path = Path(project_path)
        self.project_key = project_key
        self.holder = holder or {}
        who = ", ".join(
            f"{k}={self.holder[k]}" for k in ("Hostname", "Username", "Timestamp") if k in self.holder
        )
        super().__init__(
            f"Ghidra project {project_key!r} is in use by another process"
            + (f" ({who})" if who else "")
            + f": {self.project_path}. The lock is live, so it was not removed."
        )


def lock_files(project_path: Path, project_key: str) -> tuple[Path, Path]:
    """Return (``<key>.lock``, ``<key>.lock~``) for a project directory."""
    lock = Path(project_path) / f"{project_key}.lock"
    return lock, lock.with_name(lock.name + "~")


def read_lock_info(lock_file: Path) -> dict[str, str]:
    """Parse a Ghidra ``.lock`` properties file; {} if absent or unreadable."""
    try:
        text = Path(lock_file).read_text(encoding="latin-1")
    except OSError:
        return {}
    info: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        # java.util.Properties escapes spaces in keys as "\ "; split on the
        # first unescaped "=" or ":".
        key_chars: list[str] = []
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == "\\" and i + 1 < len(line):
                key_chars.append(line[i + 1])
                i += 2
                continue
            if ch in "=:":
                break
            key_chars.append(ch)
            i += 1
        value = line[i + 1:].strip().replace("\\:", ":")
        # Properties.store writes non-Latin-1 chars as \uXXXX (e.g. the
        # U+202F narrow no-break space in Java 21 timestamps).
        value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), value)
        info["".join(key_chars).strip()] = value
    return info


def _channel_lock_held(hold_file: Path) -> bool:
    """True if some process holds an OS lock on Ghidra's ``.lock~`` file."""
    try:
        fd = os.open(str(hold_file), os.O_RDWR)
    except FileNotFoundError:
        return False
    except PermissionError:
        # Windows sharing violation / access denied while the owner has it open.
        return True
    except OSError as e:
        if getattr(e, "winerror", None) == 32:
            return True
        raise
    try:
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                return True
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            return False
        import fcntl

        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.lockf(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def is_project_lock_held(project_path: Path, project_key: str) -> bool:
    """True if another live process holds this project's Ghidra lock.

    No ``.lock`` file -> False. A lock written without channel-locking support
    (plain "File Lock") carries no liveness signal, so it is reported as held:
    the safe answer when the owner cannot be verified.
    """
    lock, hold = lock_files(project_path, project_key)
    if not lock.exists():
        # Ghidra writes .lock before taking the channel lock; a lone held
        # .lock~ still means an owner is mid-acquire or mid-release.
        return hold.exists() and _channel_lock_held(hold)
    lock_type = read_lock_info(lock).get(_LOCK_TYPE_KEY)
    if lock_type is not None and lock_type != CHANNEL_LOCK_TYPE:
        return True
    return _channel_lock_held(hold)


def clear_stale_lock(project_path: Path, project_key: str) -> bool:
    """Remove this project's lock files only if no live process holds them.

    Returns True if the project is now unlocked (nothing to remove, or stale
    files removed), False if the lock is live or could not be removed.
    Never raises for filesystem errors.
    """
    lock, hold = lock_files(project_path, project_key)
    try:
        if is_project_lock_held(project_path, project_key):
            return False
        for f in (hold, lock):
            f.unlink(missing_ok=True)
        return True
    except OSError as e:
        logger.warning("Could not clear lock for %s at %s: %s", project_key, project_path, e)
        return False


def sweep_stale_locks(projects_dir: Path) -> dict[str, list[str]]:
    """Remove provably stale project locks under projects_dir; leave live ones.

    Covers shared projects (``<dir>/<key>/<key>.lock``) and stdio session
    projects (``<dir>/session-*/<key>/<key>.lock``). Never raises.
    """
    result: dict[str, list[str]] = {"removed": [], "live": [], "failed": []}
    projects_dir = Path(projects_dir)
    seen: set[Path] = set()
    for pattern in ("*/*.lock", "*/*.lock~", "session-*/*/*.lock", "session-*/*/*.lock~"):
        try:
            candidates = list(projects_dir.glob(pattern))
        except OSError:
            continue
        for f in candidates:
            name = f.name[:-1] if f.name.endswith("~") else f.name
            key = name[: -len(".lock")]
            proj = f.parent
            if (proj / key) in seen or proj.name != key:
                continue
            seen.add(proj / key)
            try:
                if is_project_lock_held(proj, key):
                    result["live"].append(str(proj))
                    continue
            except OSError as e:
                logger.warning("Could not probe lock for %s: %s", proj, e)
                result["failed"].append(str(proj))
                continue
            if clear_stale_lock(proj, key):
                result["removed"].append(str(proj))
            else:
                result["failed"].append(str(proj))
    if result["live"]:
        logger.info(
            "Left %d project lock(s) held by other live processes: %s",
            len(result["live"]), ", ".join(result["live"]),
        )
    if result["removed"]:
        logger.info("Removed %d stale project lock(s)", len(result["removed"]))
    return result

"""Shared test helpers."""

from pathlib import Path

import pytest


def symlink_or_skip(link: Path, target: Path) -> None:
    """Create link -> target, skipping the test where the OS forbids symlinks
    (Windows without Developer Mode / SeCreateSymbolicLinkPrivilege)."""
    try:
        link.symlink_to(target)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            pytest.skip("symlink creation needs SeCreateSymbolicLinkPrivilege on Windows")
        raise


_exit_status = 0


def pytest_sessionfinish(session, exitstatus):
    global _exit_status
    _exit_status = int(exitstatus)


@pytest.hookimpl(trylast=True)
def pytest_unconfigure(config):
    """Real-JVM (PYGHIDRA_E2E) runs: Ghidra leaves a non-daemon JVM thread
    that JPype's exit-time shutdown waits on forever, so pytest would hang
    after printing its summary. Exit with pytest's status instead (same
    reason as server._exit_after_jvm)."""
    import os
    import sys

    jpype = sys.modules.get("jpype")
    if jpype is None or not jpype.isJVMStarted():
        return
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_exit_status)

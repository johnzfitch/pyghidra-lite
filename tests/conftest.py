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

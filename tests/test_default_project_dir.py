"""Default project dir must be accepted by Ghidra 12+ (no dot-leading parts)."""

import sys
from pathlib import Path

from pyghidra_lite import backend


def test_new_default_has_no_dot_leading_component(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "LEGACY_PROJECT_DIR", tmp_path / "missing" / "projects")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    d = backend._default_project_dir()
    assert not any(p.startswith(".") for p in d.parts)
    # Accepted by the Ghidra 12 guard.
    backend._assert_ghidra_safe_project_dir(d, 12)
    if sys.platform == "win32":
        assert d == tmp_path / "AppData" / "Local" / "pyghidra-lite" / "projects"
    else:
        assert d == Path.home() / "pyghidra-lite" / "projects"


def test_existing_legacy_dir_is_kept(tmp_path, monkeypatch):
    legacy = tmp_path / ".local" / "share" / "pyghidra-lite" / "projects"
    legacy.mkdir(parents=True)
    monkeypatch.setattr(backend, "LEGACY_PROJECT_DIR", legacy)
    assert backend._default_project_dir() == legacy

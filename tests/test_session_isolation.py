"""Test session isolation for multi-agent support."""

from pathlib import Path
from pyghidra_lite.backend import GhidraBackend


def test_isolated_mode_creates_session_dir():
    """Test that isolated mode creates session-specific directories."""
    backend = GhidraBackend(shared=False)

    # Should have a session ID
    assert backend.session_id.startswith("session-")

    # Project dir should include session ID
    assert backend.session_id in str(backend.project_dir)


def test_shared_mode_uses_common_dir():
    """Test that shared mode uses common project directory."""
    backend = GhidraBackend(shared=True)

    # Should use "shared" as session ID
    assert backend.session_id == "shared"

    # Project dir should NOT include a session subdirectory
    assert "session-" not in str(backend.project_dir)


def test_multiple_isolated_backends_have_different_sessions():
    """Test that multiple isolated backends get unique sessions."""
    backend1 = GhidraBackend(shared=False)
    backend2 = GhidraBackend(shared=False)

    # Should have different session IDs
    assert backend1.session_id != backend2.session_id

    # Should have different project directories
    assert backend1.project_dir != backend2.project_dir


def test_isolated_project_dir_path_structure():
    """Test that isolated project directories have correct structure."""
    from pyghidra_lite.backend import DEFAULT_PROJECT_DIR

    backend = GhidraBackend(shared=False)

    # Should be: DEFAULT_PROJECT_DIR / session-{uuid}
    assert backend.project_dir.parent == DEFAULT_PROJECT_DIR
    assert backend.project_dir.name.startswith("session-")

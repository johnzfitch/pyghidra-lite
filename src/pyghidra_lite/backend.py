"""PyGhidra backend - manages Ghidra context and program analysis."""

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import pyghidra

from pyghidra_lite.models import AnalysisProfile, Provenance

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.base.project import GhidraProject
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program

logger = logging.getLogger(__name__)

# Standard project location
DEFAULT_PROJECT_DIR = Path.home() / ".local" / "share" / "pyghidra-lite" / "projects"

# Common Ghidra install locations to search (in priority order)
_GHIDRA_SEARCH_PATHS = [
    "/opt/ghidra",
    "/usr/share/ghidra",
    "/usr/local/share/ghidra",
    Path.home() / "ghidra",
]


def find_ghidra_install(hint: Path | str | None = None) -> Path | None:
    """Find a valid Ghidra installation directory.

    Resolution order:
        1. Explicit hint (--ghidra-dir CLI flag)
        2. GHIDRA_INSTALL_DIR environment variable
        3. Common installation paths

    A directory is valid if it contains Ghidra/application.properties.
    """
    def _is_valid(p: Path) -> bool:
        return (p / "Ghidra" / "application.properties").is_file()

    # 1. Explicit hint
    if hint:
        p = Path(hint).expanduser().resolve()
        if _is_valid(p):
            return p
        logger.warning("Provided Ghidra path is not valid: %s", p)
        return None

    # 2. Environment variable
    if env_dir := os.environ.get("GHIDRA_INSTALL_DIR"):
        p = Path(env_dir).expanduser().resolve()
        if _is_valid(p):
            return p
        logger.warning("GHIDRA_INSTALL_DIR=%s is not a valid Ghidra installation", env_dir)

    # 3. Common paths
    for candidate in _GHIDRA_SEARCH_PATHS:
        p = Path(candidate).expanduser().resolve()
        if _is_valid(p):
            logger.info("Auto-detected Ghidra at %s", p)
            return p

    # 4. Glob for versioned installs in common parent dirs
    for parent in [Path("/opt"), Path("/usr/local/share"), Path.home()]:
        if parent.is_dir():
            for child in sorted(parent.iterdir(), reverse=True):
                if child.name.startswith("ghidra") and _is_valid(child):
                    logger.info("Auto-detected Ghidra at %s", child)
                    return child

    return None


def compute_unit_id(data: bytes) -> str:
    """Content-addressed ID for a binary (in-memory bytes)."""
    return hashlib.sha256(data).hexdigest()[:16]


def compute_unit_id_streaming(path: Path, chunk_size: int = 65536) -> str:
    """Content-addressed ID using streaming hash (memory-efficient for large files).

    Args:
        path: Path to the binary file.
        chunk_size: Read chunk size in bytes (default 64KB).

    Returns:
        16-character hex hash prefix.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()[:16]


def compute_stable_id(unit_id: str, address: str) -> str:
    """Stable function ID that survives renames."""
    return hashlib.sha256(f"{unit_id}:{address}".encode()).hexdigest()[:16]


@dataclass
class ProgramHandle:
    """Handle to an analyzed program in Ghidra."""
    name: str
    unit_id: str
    program: "Program"
    flat_api: "FlatProgramAPI"
    decompiler: "DecompInterface"
    profile: AnalysisProfile
    file_path: Path | None = None
    analyzed: bool = False
    metadata: dict = field(default_factory=dict)

    def get_provenance(self) -> Provenance:
        """Get provenance info for this program."""
        from pyghidra_lite import __version__
        ghidra_version = None
        try:
            from ghidra import GhidraVersion
            ghidra_version = str(GhidraVersion.getApplicationVersion())
        except Exception:
            pass
        return Provenance(
            unit_id=self.unit_id,
            profile=self.profile,
            ghidra_version=ghidra_version,
            tool_version=__version__,
        )


class GhidraBackend:
    """Manages Ghidra project and program analysis.

    Uses separate Ghidra projects per binary to enable multi-agent parallelism.
    Each binary gets its own project directory to avoid lock contention.

    For stdio transport (one process per agent), uses session isolation.
    For SSE transport (shared server), set shared=True.
    """

    def __init__(
        self,
        project_name: str = "pyghidra_lite",
        project_dir: Path | None = None,
        default_profile: AnalysisProfile = AnalysisProfile.DEFAULT,
        shared: bool = False,
        ghidra_dir: Path | None = None,
    ):
        self.project_name = project_name
        self.project_dir = project_dir or DEFAULT_PROJECT_DIR
        self.default_profile = default_profile
        self.shared = shared
        self.ghidra_dir = ghidra_dir

        # Generate session ID for isolated mode (stdio transport)
        if not shared:
            self.session_id = f"session-{uuid.uuid4().hex[:8]}"
            self.project_dir = self.project_dir / self.session_id
        else:
            self.session_id = "shared"

        self.programs: dict[str, ProgramHandle] = {}
        self._projects: dict[str, GhidraProject] = {}  # Per-binary projects
        self._started = False

    def start(self, eager_load: bool = False) -> None:
        """Initialize PyGhidra (projects are loaded on-demand by default).

        Args:
            eager_load: If True, scan and load all existing projects at startup.
                       Default is False for multi-agent compatibility.
        """
        if self._started:
            return

        install_dir = find_ghidra_install(self.ghidra_dir)
        if install_dir is None:
            raise RuntimeError(
                "Ghidra installation not found. Provide it via one of:\n"
                "  1. --ghidra-dir /path/to/ghidra  (CLI flag)\n"
                "  2. GHIDRA_INSTALL_DIR=/path/to/ghidra  (environment variable)\n"
                "  3. Install Ghidra to /opt/ghidra or ~/ghidra"
            )

        logger.info("Starting PyGhidra (install_dir=%s)...", install_dir)
        pyghidra.start(verbose=False, install_dir=install_dir)
        self._started = True

        # Only scan existing projects if explicitly requested
        # Default is lazy loading for multi-agent support
        if eager_load:
            self._scan_existing_projects()
            logger.info(f"Backend ready. {len(self.programs)} programs loaded.")
        else:
            logger.info("Backend ready (lazy loading enabled).")

    def _get_or_create_project_for_binary(self, unit_id: str) -> "GhidraProject":
        """Get or create a Ghidra project for a specific binary (by unit_id)."""
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        # Use unit_id as project name for isolation
        project_path = self.project_dir / unit_id
        project_path.mkdir(exist_ok=True, parents=True)
        project_str = str(project_path.absolute())

        locator = ProjectLocator(project_str, unit_id)
        try:
            if locator.exists():
                logger.debug(f"Opening existing project: {unit_id}")
                return GhidraProject.openProject(project_str, unit_id, True)
            else:
                logger.info(f"Creating new project: {unit_id}")
                return GhidraProject.createProject(project_str, unit_id, False)
        except Exception as e:
            if "LockException" in str(type(e).__name__) or "Unable to lock" in str(e):
                lock_file = project_path / f"{unit_id}.lock"
                raise RuntimeError(
                    f"Binary {unit_id} is locked by another process.\n"
                    f"Either stop the other process or delete: {lock_file}"
                ) from e
            raise

    def _scan_existing_projects(self) -> None:
        """Scan project directory for existing per-binary projects and load them."""
        if not self.project_dir.exists():
            return

        for project_path in self.project_dir.iterdir():
            if not project_path.is_dir():
                continue

            unit_id = project_path.name
            # Check if it's a valid Ghidra project (has .gpr file)
            if not (project_path / f"{unit_id}.gpr").exists():
                continue

            try:
                project = self._get_or_create_project_for_binary(unit_id)
                self._projects[unit_id] = project

                # Load programs from this project
                root_folder = project.getRootFolder()
                for domain_file in root_folder.getFiles():
                    if domain_file.getContentType() == "Program":
                        prog_name = domain_file.getName()
                        try:
                            program = project.openProgram("/", prog_name, False)
                            handle = self._init_program_handle(program, prog_name)
                            self.programs[prog_name] = handle
                            logger.info(f"Loaded: {prog_name}")
                        except Exception as e:
                            logger.warning(f"Failed to load {prog_name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to load project {unit_id}: {e}")

    def _init_program_handle(
        self,
        program: "Program",
        name: str,
        profile: AnalysisProfile | None = None,
    ) -> ProgramHandle:
        """Initialize a ProgramHandle for a loaded program."""
        from ghidra.app.decompiler import DecompileOptions, DecompInterface
        from ghidra.program.flatapi import FlatProgramAPI

        # Set up decompiler
        decomp = DecompInterface()
        options = DecompileOptions()
        options.grabFromProgram(program)
        options.setMaxPayloadMBytes(100)
        decomp.setOptions(options)
        decomp.openProgram(program)

        # Get metadata
        metadata = dict(program.getMetadata())

        # Compute unit_id from executable
        unit_id = "unknown"
        exe_path = metadata.get("Executable Location")
        if exe_path and Path(exe_path).exists():
            with open(exe_path, "rb") as f:
                unit_id = compute_unit_id(f.read())

        return ProgramHandle(
            name=name,
            unit_id=unit_id,
            program=program,
            flat_api=FlatProgramAPI(program),
            decompiler=decomp,
            profile=profile or self.default_profile,
            file_path=Path(exe_path) if exe_path else None,
            analyzed=True,  # Existing programs are analyzed
            metadata=metadata,
        )

    def import_binary(
        self,
        path: Path | str,
        profile: AnalysisProfile | str | None = None,
        analyze: bool = True,
    ) -> ProgramHandle:
        """Import and optionally analyze a binary."""
        if not self._started:
            self.start()

        # Convert string to Path if needed
        if isinstance(path, str):
            path = Path(path)

        # Convert string to enum if needed
        if isinstance(profile, str):
            profile = AnalysisProfile(profile)
        profile = profile or self.default_profile
        path = path.resolve()

        # Generate unique ID using streaming hash (memory-efficient)
        unit_id = compute_unit_id_streaming(path)

        # Check if already imported
        for handle in self.programs.values():
            if handle.unit_id == unit_id:
                logger.info("Program already imported (unit_id match): %s", handle.name)
                return handle

        prog_name = f"{path.name}-{unit_id[:8]}"

        # Get or create project for this binary
        if unit_id not in self._projects:
            project = self._get_or_create_project_for_binary(unit_id)
            self._projects[unit_id] = project
        else:
            project = self._projects[unit_id]

        # Check if program exists in this binary's project
        root_folder = project.getRootFolder()
        if root_folder.getFile(prog_name):
            logger.info(f"Opening existing program: {prog_name}")
            program = project.openProgram("/", prog_name, False)
        else:
            logger.info(f"Importing: {prog_name}")
            program = project.importProgram(path)
            if not program:
                raise ImportError(f"Failed to import: {path}")
            program.name = prog_name
            project.saveAs(program, "/", prog_name, True)

        handle = self._init_program_handle(program, prog_name, profile)
        handle.analyzed = False
        handle.file_path = path
        self.programs[prog_name] = handle

        if analyze:
            self.analyze_program(prog_name, profile)

        return handle

    def analyze_program(
        self,
        name: str,
        profile: AnalysisProfile | str | None = None,
    ) -> None:
        """Analyze a program with the specified profile."""
        if name not in self.programs:
            raise ValueError(f"Program not found: {name}")

        handle = self.programs[name]
        # Convert string to enum if needed
        if isinstance(profile, str):
            profile = AnalysisProfile(profile)
        profile = profile or handle.profile

        logger.info(f"Analyzing {name} with profile={profile.value}")
        self._apply_profile(handle, profile)

        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.util import GhidraProgramUtilities

        # Start transaction for program modifications
        tx_id = handle.program.startTransaction("Analysis")
        tx_success = False
        try:
            GhidraScriptUtil.acquireBundleHostReference()
            handle.flat_api.analyzeAll(handle.program)

            if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                GhidraProgramUtilities.setAnalyzedFlag(handle.program, True)
            elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                GhidraProgramUtilities.markProgramAnalyzed(handle.program)

            tx_success = True
        finally:
            # End transaction (commit if successful, rollback if failed)
            handle.program.endTransaction(tx_id, tx_success)
            GhidraScriptUtil.releaseBundleHostReference()
            # Save to the binary's project
            if tx_success and handle.unit_id in self._projects:
                self._projects[handle.unit_id].save(handle.program)

        handle.analyzed = True
        handle.profile = profile
        logger.info(f"Analysis complete: {name}")

    def _apply_profile(self, handle: ProgramHandle, profile: AnalysisProfile) -> None:
        """Apply analysis profile settings."""
        from ghidra.program.model.listing import Program

        prog = handle.program
        options = prog.getOptions(Program.ANALYSIS_PROPERTIES)

        if profile == AnalysisProfile.FAST:
            # Disable all expensive analyzers for quick triage (<60s).
            # Keeps: entry point, subroutine refs, basic blocks, ASCII strings,
            # symbol table, imports/exports — enough for function listing,
            # string search, and on-demand decompilation.
            slow_analyzers = [
                "Decompiler Parameter ID",
                "Stack",
                "Non-Returning Functions - Discovered",
                "Aggressive Instruction Finder",
                "Function Start Search",
                "DWARF",
                "PDB Universal",
                "PDB MSDIA",
                "Embedded Media",
                "Scalar Operand References",
                "Data Reference",
                "GCC Exception Handlers",
                "Windows x86 PE Exception Handling",
                "Apply Data Archives",
                "Shared Return Calls",
                "Condense Filler Bytes",
                "Function Start Search After Code",
                "Function Start Search After Data",
                "Demangler GNU",
                "Demangler Microsoft",
            ]
            for name in slow_analyzers:
                self._set_option(options, name, False)
            logger.debug("Applied FAST profile: disabled %d slow analyzers", len(slow_analyzers))
        elif profile == AnalysisProfile.DEEP:
            # Enable thorough analysis
            self._set_option(options, "Decompiler Parameter ID", True)
            self._set_option(options, "Aggressive Instruction Finder", True)
            logger.debug("Applied DEEP profile")
        # DEFAULT uses Ghidra defaults

    def _set_option(self, options, name: str, value) -> None:
        """Set an analysis option safely."""
        try:
            opt_type = str(options.getType(name))
            if opt_type == "BOOLEAN_TYPE":
                options.setBoolean(name, value)
            elif opt_type == "INT_TYPE":
                options.setInt(name, int(value))
            elif opt_type == "STRING_TYPE":
                options.setString(name, str(value))
        except Exception as e:
            logger.debug(f"Could not set option {name}: {e}")

    def get_program(self, name: str) -> ProgramHandle:
        """Get a program handle by name."""
        if name not in self.programs:
            # Try partial match
            matches = [n for n in self.programs if name in n]
            if len(matches) == 1:
                name = matches[0]
            elif matches:
                raise ValueError(f"Ambiguous name '{name}'. Matches: {matches}")
            else:
                available = list(self.programs.keys())
                raise ValueError(f"Program not found: {name}. Available: {available}")
        return self.programs[name]

    def delete_program(self, name: str) -> bool:
        """Delete a program from its project."""
        if name not in self.programs:
            return False

        handle = self.programs[name]
        unit_id = handle.unit_id

        if unit_id in self._projects:
            project = self._projects[unit_id]
            try:
                df = handle.program.getDomainFile()
                project.close(handle.program)
                df.delete()
                del self.programs[name]
                logger.info(f"Deleted: {name}")

                # If this was the last program in the project, close it
                remaining = [p for p in self.programs.values() if p.unit_id == unit_id]
                if not remaining:
                    project.close()
                    del self._projects[unit_id]
                    logger.debug(f"Closed empty project: {unit_id}")

                return True
            except Exception as e:
                logger.error(f"Failed to delete {name}: {e}")
                return False
        return False

    def list_programs(self) -> list[str]:
        """List all programs in the project."""
        return list(self.programs.keys())

    def close(self) -> None:
        """Close all programs and projects."""
        # Close all programs
        for name, handle in list(self.programs.items()):
            try:
                if handle.unit_id in self._projects:
                    self._projects[handle.unit_id].close(handle.program)
            except Exception as e:
                logger.warning(f"Error closing {name}: {e}")

        # Close all projects
        for unit_id, project in list(self._projects.items()):
            try:
                project.close()
            except Exception as e:
                logger.warning(f"Error closing project {unit_id}: {e}")

        self.programs.clear()
        self._projects.clear()
        logger.info("Backend closed")

"""PyGhidra backend - manages Ghidra context and program analysis."""

import hashlib
import logging
import os
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


def compute_unit_id(data: bytes) -> str:
    """Content-addressed ID for a binary."""
    return hashlib.sha256(data).hexdigest()[:16]


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
    """Manages Ghidra project and program analysis."""

    def __init__(
        self,
        project_name: str = "pyghidra_lite",
        project_dir: Path | None = None,
        default_profile: AnalysisProfile = AnalysisProfile.DEFAULT,
    ):
        self.project_name = project_name
        self.project_dir = project_dir or DEFAULT_PROJECT_DIR
        self.default_profile = default_profile
        self.programs: dict[str, ProgramHandle] = {}
        self._project: "GhidraProject | None" = None
        self._started = False

    def start(self) -> None:
        """Initialize PyGhidra and open/create project."""
        if self._started:
            return

        logger.info("Starting PyGhidra...")
        pyghidra.start(verbose=False)
        self._started = True

        self._project = self._get_or_create_project()
        self._load_existing_programs()
        logger.info(f"Backend ready. Project: {self.project_name}")

    def _get_or_create_project(self) -> "GhidraProject":
        """Get or create the Ghidra project."""
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        project_path = self.project_dir / self.project_name
        project_path.mkdir(exist_ok=True, parents=True)
        project_str = str(project_path.absolute())

        locator = ProjectLocator(project_str, self.project_name)
        if locator.exists():
            logger.info(f"Opening existing project: {self.project_name}")
            return GhidraProject.openProject(project_str, self.project_name, True)
        else:
            logger.info(f"Creating new project: {self.project_name}")
            return GhidraProject.createProject(project_str, self.project_name, False)

    def _load_existing_programs(self) -> None:
        """Load programs already in the project."""
        if not self._project:
            return

        root_folder = self._project.getRootFolder()
        for domain_file in root_folder.getFiles():
            if domain_file.getContentType() == "Program":
                name = domain_file.getName()
                try:
                    program = self._project.openProgram("/", name, False)
                    handle = self._init_program_handle(program, name)
                    self.programs[name] = handle
                    logger.info(f"Loaded existing program: {name}")
                except Exception as e:
                    logger.warning(f"Failed to load {name}: {e}")

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
        path: Path,
        profile: AnalysisProfile | None = None,
        analyze: bool = True,
    ) -> ProgramHandle:
        """Import and optionally analyze a binary."""
        if not self._started:
            self.start()

        if not self._project:
            raise RuntimeError("Project not initialized")

        profile = profile or self.default_profile
        path = path.resolve()

        # Generate unique name
        with open(path, "rb") as f:
            data = f.read()
        unit_id = compute_unit_id(data)
        prog_name = f"{path.name}-{unit_id[:6]}"

        # Check if already imported
        if prog_name in self.programs:
            logger.info(f"Program already imported: {prog_name}")
            return self.programs[prog_name]

        # Check if in project
        root_folder = self._project.getRootFolder()
        if root_folder.getFile(prog_name):
            logger.info(f"Opening existing program: {prog_name}")
            program = self._project.openProgram("/", prog_name, False)
        else:
            logger.info(f"Importing: {prog_name}")
            program = self._project.importProgram(path)
            if not program:
                raise ImportError(f"Failed to import: {path}")
            program.name = prog_name
            self._project.saveAs(program, "/", prog_name, True)

        handle = self._init_program_handle(program, prog_name, profile)
        handle.analyzed = False
        self.programs[prog_name] = handle

        if analyze:
            self.analyze_program(prog_name, profile)

        return handle

    def analyze_program(
        self,
        name: str,
        profile: AnalysisProfile | None = None,
    ) -> None:
        """Analyze a program with the specified profile."""
        if name not in self.programs:
            raise ValueError(f"Program not found: {name}")

        handle = self.programs[name]
        profile = profile or handle.profile

        logger.info(f"Analyzing {name} with profile={profile.value}")
        self._apply_profile(handle, profile)

        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.util import GhidraProgramUtilities

        try:
            GhidraScriptUtil.acquireBundleHostReference()
            handle.flat_api.analyzeAll(handle.program)

            if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                GhidraProgramUtilities.setAnalyzedFlag(handle.program, True)
            elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                GhidraProgramUtilities.markProgramAnalyzed(handle.program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
            if self._project:
                self._project.save(handle.program)

        handle.analyzed = True
        handle.profile = profile
        logger.info(f"Analysis complete: {name}")

    def _apply_profile(self, handle: ProgramHandle, profile: AnalysisProfile) -> None:
        """Apply analysis profile settings."""
        from ghidra.program.model.listing import Program

        prog = handle.program
        options = prog.getOptions(Program.ANALYSIS_PROPERTIES)

        if profile == AnalysisProfile.FAST:
            # Disable slow analyzers
            self._set_option(options, "Decompiler Parameter ID", False)
            self._set_option(options, "Stack", False)
            logger.debug("Applied FAST profile")
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
                raise ValueError(f"Program not found: {name}. Available: {list(self.programs.keys())}")
        return self.programs[name]

    def delete_program(self, name: str) -> bool:
        """Delete a program from the project."""
        if name not in self.programs:
            return False

        handle = self.programs[name]
        if self._project:
            try:
                df = handle.program.getDomainFile()
                self._project.close(handle.program)
                df.delete()
                del self.programs[name]
                logger.info(f"Deleted: {name}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete {name}: {e}")
                return False
        return False

    def list_programs(self) -> list[str]:
        """List all programs in the project."""
        return list(self.programs.keys())

    def close(self) -> None:
        """Close all programs and the project."""
        for name, handle in list(self.programs.items()):
            try:
                if self._project:
                    self._project.close(handle.program)
            except Exception as e:
                logger.warning(f"Error closing {name}: {e}")

        if self._project:
            self._project.close()
            self._project = None

        self.programs.clear()
        logger.info("Backend closed")

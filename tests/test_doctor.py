"""pyghidra-lite doctor: read-only environment checks."""

import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyghidra_lite import doctor
from pyghidra_lite.doctor import FAIL, OK, WARN


def _fake_ghidra(root: Path, version="12.1.2", java_min="21", java_max="", plat=None) -> Path:
    props = root / "Ghidra" / "application.properties"
    props.parent.mkdir(parents=True)
    props.write_text(
        f"application.name=Ghidra\napplication.version={version}\n"
        f"application.java.min={java_min}\napplication.java.max={java_max}\n"
    )
    plat = plat or doctor.decompiler_platform()
    d = root / "Ghidra" / "Features" / "Decompiler" / "os" / plat
    d.mkdir(parents=True)
    (d / ("decompile.exe" if plat.startswith("win") else "decompile")).write_bytes(b"")
    return root


@pytest.mark.parametrize("out,major", [
    ('openjdk version "21.0.11" 2026-04-21 LTS', 21),
    ('java version "1.8.0_402"', 8),
    ('openjdk version "17" 2021-09-14', 17),
    ("garbage", None),
])
def test_parse_java_major(out, major):
    assert doctor.parse_java_major(out) == major


def test_ghidra_found_and_versioned(tmp_path):
    root = _fake_ghidra(tmp_path / "ghidra_12.1.2_PUBLIC")
    check, install, props = doctor.check_ghidra(root)
    assert check.status == OK and "12.1.2" in check.detail
    assert install == root.resolve() and props["application.java.min"] == "21"


def test_ghidra_missing(tmp_path):
    check, install, _ = doctor.check_ghidra(tmp_path / "nope")
    assert check.status == FAIL and install is None and check.fix


def test_decompiler_present_and_missing(tmp_path):
    root = _fake_ghidra(tmp_path / "g")
    assert doctor.check_decompiler(root).status == OK
    other = "linux_arm_64" if doctor.decompiler_platform() != "linux_arm_64" else "win_x86_64"
    root2 = _fake_ghidra(tmp_path / "g2", plat=other)
    assert doctor.check_decompiler(root2).status == FAIL


def _fake_java(monkeypatch, tmp_path, version_text, javac=True):
    bindir = tmp_path / "jdk" / "bin"
    bindir.mkdir(parents=True)
    exe = bindir / "java"
    exe.write_bytes(b"")
    if javac:
        (bindir / "javac").write_bytes(b"")
    monkeypatch.setattr(doctor, "_find_java", lambda: (exe, "JAVA_HOME"))
    monkeypatch.setattr(
        doctor.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="", stderr=version_text),
    )


def test_java_in_range(monkeypatch, tmp_path):
    _fake_java(monkeypatch, tmp_path, 'openjdk version "21.0.11"\nOpenJDK 64-Bit Server VM')
    checks = doctor.check_java({"application.java.min": "21", "application.java.max": ""})
    assert [c.status for c in checks] == [OK]


def test_java_too_old(monkeypatch, tmp_path):
    _fake_java(monkeypatch, tmp_path, 'openjdk version "17.0.2"\nOpenJDK 64-Bit Server VM')
    checks = doctor.check_java({"application.java.min": "21", "application.java.max": ""})
    assert checks[0].status == FAIL and "needs >= 21" in checks[0].detail


def test_jre_without_javac_warns(monkeypatch, tmp_path):
    _fake_java(monkeypatch, tmp_path, 'openjdk version "21"\nOpenJDK 64-Bit Server VM', javac=False)
    checks = doctor.check_java({"application.java.min": "21"})
    assert [c.status for c in checks] == [OK, WARN]


def test_project_dir_dotted_fails_only_on_ghidra_12(tmp_path):
    dotted = tmp_path / ".hidden" / "projects"
    assert doctor.check_project_dir(dotted, 12)[0].status == FAIL
    assert doctor.check_project_dir(dotted, 11)[0].status == OK
    assert doctor.check_project_dir(tmp_path / "projects", 12)[0].status == OK


def test_cli_exit_code_and_json(tmp_path, monkeypatch):
    from pyghidra_lite.server import cli

    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    root = _fake_ghidra(tmp_path / "ghidra")
    _fake_java(monkeypatch, tmp_path, 'openjdk version "21.0.11"\nOpenJDK 64-Bit Server VM')
    monkeypatch.setattr(doctor, "check_backend", lambda port: doctor.Check("backend", "info", "skipped"))
    runner = CliRunner()
    ok = runner.invoke(cli, ["doctor", "--json", "--ghidra-dir", str(root),
                             "--project-dir", str(tmp_path / "projects")])
    assert ok.exit_code == 0, ok.output
    assert '"name": "decompiler"' in ok.output
    bad = runner.invoke(cli, ["doctor", "--ghidra-dir", str(tmp_path / "missing"),
                              "--project-dir", str(tmp_path / "projects")])
    assert bad.exit_code == 1 and "[FAIL] ghidra" in bad.output

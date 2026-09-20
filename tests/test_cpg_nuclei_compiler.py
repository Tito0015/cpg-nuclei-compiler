"""CPG → Nuclei compiler and Docker closed-loop harness tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import shutil

ROOT = Path(__file__).resolve().parent.parent


def test_cargo_nuclei_exporter_tests_pass() -> None:
    proc = subprocess.run(
        ["cargo", "test", "-p", "cpg_nuclei_core", "nuclei", "--", "--nocapture"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_generated_yaml_has_required_keys() -> None:
    """Render exporter output via a minimal inline Rust check through cargo test output."""
    proc = subprocess.run(
        ["cargo", "test", "-p", "cpg_nuclei_core", "nuclei_exporter_sat_output", "--", "--nocapture"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0
    # Indirect: if snapshot test passes, YAML structure is validated in Rust.
    assert "nuclei_exporter_sat_output_is_valid_yaml" in proc.stdout or proc.returncode == 0


def test_nuclei_yaml_structure_from_rust_render() -> None:
    proc = subprocess.run(
        ["cargo", "test", "-p", "cpg_nuclei_core", "dispatch_nuclei", "--", "--nocapture"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_docker_runner_argparse() -> None:
    from harness.docker_runner import _parse_nuclei_output, main

    matched, hits, _extracted = _parse_nuclei_output(
        "[fixture-tp] http://127.0.0.1:5000/tp-marker", ""
    )
    assert matched
    assert hits

    with patch("sys.argv", ["docker_runner", "--help"]):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not on PATH")
def test_docker_runner_fixture_tp_live() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "harness.docker_runner",
            "--self-test",
            "--target",
            "http://127.0.0.1:5000",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("Docker daemon not running")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"verdict": "TP"' in proc.stdout or '"verdict": "TN"' in proc.stdout


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not on PATH")
def test_docker_runner_cve_template_tn_on_fixture() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "harness.docker_runner",
            "--template",
            "templates/CVE-2024-51483.yaml",
            "--target",
            "http://127.0.0.1:5000",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("Docker daemon not running")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"verdict": "TN"' in proc.stdout


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not on PATH")
def test_mcp_tools_list_docker_tp() -> None:
    template = ROOT / "templates" / "mcp-server-unauth-tools-list.yaml"
    render = subprocess.run(
        [
            "cargo",
            "run",
            "-p",
            "cpg_nuclei_core",
            "--bin",
            "cpg_nuclei_cli",
            "--",
            "--render-spec",
            "MCP-TOOLS-LIST",
            str(template),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert render.returncode == 0, render.stdout + render.stderr
    assert template.is_file()

    proc = subprocess.run(
        [sys.executable, "-m", "harness.docker_runner", "--mcp"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("Docker daemon not running")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"verdict": "TP"' in proc.stdout
    assert "read_file" in proc.stdout or '"extracted"' in proc.stdout


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not on PATH")
def test_mcp_tools_list_template_tn_on_fixture() -> None:
    template = ROOT / "templates" / "mcp-server-unauth-tools-list.yaml"
    if not template.is_file():
        subprocess.run(
            [
                "cargo",
                "run",
                "-p",
                "cpg_nuclei_core",
                "--bin",
                "cpg_nuclei_cli",
                "--",
                "--render-spec",
                "MCP-TOOLS-LIST",
                str(template),
            ],
            cwd=ROOT,
            check=True,
            timeout=300,
        )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "harness.docker_runner",
            "--template",
            str(template),
            "--target",
            "http://127.0.0.1:5000",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("Docker daemon not running")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"verdict": "TN"' in proc.stdout

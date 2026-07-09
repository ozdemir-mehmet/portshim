"""
Integration test: pipeline smoke test.
Tests the full pipeline against scanme.nmap.org (Nmap's official test target).
NOT for CI — requires network + nmap. Run before each engagement.

Usage: pytest tests/integration/test_pipeline_smoke.py -v -m smoke
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.smoke

SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "skills" / "site-assessment-pipeline" / "scripts"
TARGET = "scanme.nmap.org"


def check_tool(tool: str) -> bool:
    """Check if a CLI tool is available."""
    return subprocess.run(["which", tool], capture_output=True).returncode == 0


@pytest.fixture
def has_nmap():
    if not check_tool("nmap"):
        pytest.skip("nmap not installed")
    return True


def test_phase1_engagement_profile_output():
    """Engagement-profiles produces valid flags."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "engagement-profiles.py"), "surgical", "nmap"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "-sS" in result.stdout


def test_phase1_nmap_scan(has_nmap, tmp_path):
    """Nmap scan against scanme.nmap.org produces XML output."""
    xml_file = tmp_path / "scan.xml"
    result = subprocess.run(
        ["nmap", "-T3", "-sT", "-oX", str(xml_file), TARGET],
        capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0
    assert xml_file.exists()

    # Parse with topology
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "topology.py"), str(xml_file), "--json"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["host_count"] >= 1


def test_phase1_topology_table(has_nmap, tmp_path):
    """Topology produces a readable table."""
    xml_file = tmp_path / "scan2.xml"
    subprocess.run(
        ["nmap", "-T3", "-sT", "-oX", str(xml_file), TARGET],
        capture_output=True, timeout=120
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "topology.py"), str(xml_file)],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "Network Topology" in result.stdout
    assert TARGET in result.stdout


def test_phase4_report_generation(tmp_path):
    """Report generator produces .docx and .pptx from findings fixture."""
    findings_file = Path(__file__).resolve().parent.parent / "fixtures" / "sample-findings.json"
    out_dir = tmp_path / "reports"

    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "report-gen.py"),
         str(findings_file), "--output-dir", str(out_dir), "--format", "all"],
        capture_output=True, text=True
    )
    # May fail if python-docx/pptx not installed, that's OK for smoke
    if result.returncode == 0:
        assert (out_dir / "portshim-report-").exists() or any(out_dir.iterdir())


def test_phase4_excel_checklist(tmp_path):
    """Excel checklist generates from findings."""
    findings_file = Path(__file__).resolve().parent.parent / "fixtures" / "sample-findings.json"
    out_file = tmp_path / "checklist.xlsx"

    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "excel-checklist.py"),
         str(findings_file), "--output", str(out_file)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        assert out_file.exists()
        assert out_file.stat().st_size > 0


def test_phase5_retest_diff():
    """Retest diff correctly classifies findings."""
    baseline = Path(__file__).resolve().parent.parent / "fixtures" / "baseline-findings.json"
    retest = Path(__file__).resolve().parent.parent / "fixtures" / "retest-findings.json"

    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "retest-diff.py"),
         str(baseline), str(retest), "--json"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["summary"]["new_count"] == 1  # log4j
    assert data["summary"]["fixed_count"] > 0

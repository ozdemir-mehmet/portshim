"""
UAT tests for PortShim wired pipeline.

Fixtures in tests/fixtures/uat/ — see references/uat/wired-pipeline-uat.md for spec.

Usage:
    pytest tests/test_uat_wired.py -v                        # All UAT tests
    pytest tests/test_uat_wired.py -v -m "not network"       # Fixture-only
    pytest tests/test_uat_wired.py -v -k "test_w07"          # Phase 1 only
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PROJECT_ROOT / "skills" / "site-assessment-pipeline" / "scripts"
VENV_PYTHON = str(PROJECT_ROOT / ".venv" / "bin" / "python")
PYTHON = VENV_PYTHON if Path(VENV_PYTHON).exists() else sys.executable
UAT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "uat"
TARGET = "scanme.nmap.org"

pytestmark = pytest.mark.uat


# ═══════════════════════════════════════════════════════════════════
# W-00: Repo sync — local clone vs origin (testing only, not in CLI)
# ═══════════════════════════════════════════════════════════════════

class TestRepoInSync:
    """Pre-flight: verify local repo matches origin before pipeline tests."""

    def test_not_behind_origin(self):
        """Pipeline must not run with outdated scripts."""
        subprocess.run(
            ["git", "fetch", "origin"],
            capture_output=True, timeout=30,
            cwd=PROJECT_ROOT,
        )
        result = subprocess.run(
            ["git", "rev-list", "--left-right", "--count", "origin/main...HEAD"],
            capture_output=True, text=True, timeout=10,
            cwd=PROJECT_ROOT,
        )
        behind, ahead = result.stdout.strip().split()
        assert behind == "0", (
            f"Repo is {behind} commits behind origin/main. "
            f"Pipeline would use outdated scripts."
        )

    def test_working_tree_clean(self):
        """Uncommitted changes make results unreproducible."""
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=10,
            cwd=PROJECT_ROOT,
        )
        dirty = result.stdout.strip()
        assert not dirty, (
            f"Uncommitted changes detected:\n{dirty}"
        )

    def test_on_main_branch(self):
        """Warn if not on main — pipeline may include unreviewed code."""
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True, text=True, timeout=10,
            cwd=PROJECT_ROOT,
        )
        branch = result.stdout.strip()
        assert branch == "main", (
            f"On branch '{branch}', not 'main'. "
            f"Pipeline may include unreviewed changes."
        )


# ═══════════════════════════════════════════════════════════════════
# W-02: Engagement profiles
# ═══════════════════════════════════════════════════════════════════

def _profile(tool, profile="surgical"):
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "engagement-profiles.py"), profile, tool],
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestEngagementProfiles:
    def test_silent_entry_nmap(self):
        rc, out, _ = _profile("nmap", "silent-entry")
        assert rc == 0
        assert "-T1" in out
        assert "-sT" in out
        assert "--scan-delay 30s" in out

    def test_silent_entry_nuclei_disabled(self):
        rc, out, _ = _profile("nuclei", "silent-entry")
        assert rc == 2
        assert out == "DISABLED"

    def test_surgical_nmap(self):
        rc, out, _ = _profile("nmap", "surgical")
        assert rc == 0
        assert "-T3" in out
        assert "-sS" in out

    def test_full_assault_nmap(self):
        rc, out, _ = _profile("nmap", "full-assault")
        assert rc == 0
        assert "-T5" in out
        assert "-A" in out
        assert "--script vuln" in out

    def test_brute_force_silent_entry(self):
        rc, out, _ = _profile("brute_force", "silent-entry")
        assert rc == 0
        assert out == "false"

    def test_brute_force_surgical(self):
        rc, out, _ = _profile("brute_force", "surgical")
        assert rc == 0
        assert out == "common-only"

    def test_invalid_profile(self):
        rc, _, err = _profile("nmap", "stealth")
        assert rc == 1
        assert "Unknown profile" in err
        assert "silent-entry" in err

    def test_invalid_tool(self):
        rc, _, err = _profile("nmap2", "surgical")
        assert rc == 1
        assert "Unknown tool" in err


# ═══════════════════════════════════════════════════════════════════
# W-07: topology.py
# ═══════════════════════════════════════════════════════════════════

def _topology(args):
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "topology.py")] + args,
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestTopology:
    def test_empty_xml(self):
        rc, out, _ = _topology([str(UAT_FIXTURES / "nmap-empty.xml")])
        assert rc == 0
        assert "0 hosts" in out or "Total hosts: 0" in out

    def test_empty_xml_json(self):
        rc, out, _ = _topology([str(UAT_FIXTURES / "nmap-empty.xml"), "--json"])
        assert rc == 0
        data = json.loads(out)
        assert data["host_count"] == 0

    def test_malformed_xml(self):
        """Graceful: prints error to stderr, exits 0 with 0 hosts."""
        rc, out, err = _topology([str(UAT_FIXTURES / "nmap-malformed.xml")])
        assert rc == 0
        assert "Error parsing" in err

    def test_null_hostname_table(self):
        """Null hostname renders fine in table mode."""
        rc, out, _ = _topology([str(UAT_FIXTURES / "nmap-null-hostname.xml")])
        assert rc == 0
        assert "2 hosts" in out or "Total hosts: 2" in out

    def test_null_hostname_dot(self):
        """B1 fix: DOT mode handles null hostname gracefully."""
        rc, out, _ = _topology([str(UAT_FIXTURES / "nmap-null-hostname.xml"), "--dot"])
        assert rc == 0
        assert "digraph" in out
        assert "192.168.1.100" in out


# ═══════════════════════════════════════════════════════════════════
# W-08: report-gen.py
# ═══════════════════════════════════════════════════════════════════

def _report_gen(findings_file, extra_args=None):
    import tempfile
    out_dir = tempfile.mkdtemp(prefix="uat_report_")
    cmd = [PYTHON, str(SCRIPTS / "report-gen.py"), str(findings_file),
           "--output-dir", out_dir, "--format", "docx"]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr, out_dir


class TestReportGen:
    def test_dict_wrapped_friendly_error(self):
        """B2 fix: dict-wrapped findings → friendly error message."""
        rc, _, err, _ = _report_gen(UAT_FIXTURES / "findings-dict-wrapped.json")
        assert rc == 1
        assert "expected a JSON array" in err
        assert "findings" in err
        assert "AttributeError" not in err

    def test_invalid_json_friendly_error(self, tmp_path):
        """B3 fix: invalid JSON → friendly error, not raw traceback."""
        bad = tmp_path / "bad.json"
        bad.write_text('not valid json at all {{{')
        rc, _, err, _ = _report_gen(bad)
        assert rc == 1
        assert "not valid JSON" in err
        assert "JSONDecodeError" not in err

    def test_empty_findings(self):
        rc, out, _, _ = _report_gen(UAT_FIXTURES / "findings-empty.json")
        # Should handle gracefully — no crash
        assert rc == 0

    def test_solo_finding(self):
        """Single finding doesn't cause divide-by-zero."""
        rc, out, _, _ = _report_gen(UAT_FIXTURES / "findings-solo.json")
        assert rc == 0
        assert "Generated" in out


# ═══════════════════════════════════════════════════════════════════
# W-09: excel-checklist.py
# ═══════════════════════════════════════════════════════════════════

def _excel_checklist(findings_file):
    import tempfile
    out_file = Path(tempfile.mkdtemp()) / "checklist.xlsx"
    result = subprocess.run(
        [PYTHON, str(SCRIPTS / "excel-checklist.py"), str(findings_file),
         "--output", str(out_file)],
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout, result.stderr, out_file


class TestExcelChecklist:
    def test_generates_valid_xlsx(self):
        rc, out, _, out_file = _excel_checklist(
            PROJECT_ROOT / "tests" / "fixtures" / "sample-findings.json"
        )
        assert rc == 0
        assert out_file.exists()
        assert out_file.stat().st_size > 0

    def test_empty_findings(self):
        """B6 fix: empty findings → valid XLSX with headers only."""
        rc, out, _, out_file = _excel_checklist(UAT_FIXTURES / "findings-empty.json")
        assert rc == 0
        assert out_file.exists()
        assert out_file.stat().st_size > 0


# ═══════════════════════════════════════════════════════════════════
# W-10: retest-diff.py
# ═══════════════════════════════════════════════════════════════════

class TestRetestDiff:
    def test_classification(self):
        baseline = PROJECT_ROOT / "tests" / "fixtures" / "baseline-findings.json"
        retest = PROJECT_ROOT / "tests" / "fixtures" / "retest-findings.json"
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "retest-diff.py"),
             str(baseline), str(retest), "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["summary"]["fixed_count"] == 4
        assert data["summary"]["new_count"] == 1
        assert data["summary"]["still_open_count"] > 0
        assert data["summary"]["regression_count"] == 0


# ═══════════════════════════════════════════════════════════════════
# W-00 / W-06: Scan pre-flight (network-dependent)
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.network
class TestScanPreFlight:
    def test_dry_run_hybrid(self):
        result = subprocess.run(
            [PYTHON, str(PROJECT_ROOT / "portshim"), "scan",
             TARGET, "--dry-run"],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT,
        )
        assert result.returncode == 0
        assert "Would start llama-server" in result.stdout
        assert "Ready to Start" in result.stdout

    def test_dry_run_cloud_no_server(self):
        result = subprocess.run(
            [PYTHON, str(PROJECT_ROOT / "portshim"), "scan",
             TARGET, "--dry-run", "--mode", "cloud"],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT,
        )
        assert result.returncode == 0
        assert "Would start llama-server" not in result.stdout

    def test_dry_run_no_server_flag(self):
        result = subprocess.run(
            [PYTHON, str(PROJECT_ROOT / "portshim"), "scan",
             TARGET, "--dry-run", "--no-server"],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT,
        )
        assert result.returncode == 0
        assert "Would start llama-server" not in result.stdout

    def test_invalid_engagement_rejected(self):
        result = subprocess.run(
            [PYTHON, str(PROJECT_ROOT / "portshim"), "scan",
             TARGET, "--engagement", "stealth"],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT,
        )
        assert result.returncode != 0
        assert "invalid choice" in result.stderr.lower()

"""Tests for scripts/test_report.py — save test results to outputs/reports/."""

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── Test: parse_junit_xml() ──


class TestParseJunitXml:
    """Tests for JUnit XML parsing into structured results."""

    def test_parses_passing_tests(self, tmp_path):
        """Parses a JUnit XML with passing tests."""
        from scripts.test_report import parse_junit_xml

        xml = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="0" failures="0" skipped="0" tests="3" time="1.234">
    <testcase classname="tests.test_wireless_scan" name="test_dry_run" time="0.010"/>
    <testcase classname="tests.test_wireless_scan" name="test_force_flag" time="0.005"/>
    <testcase classname="tests.test_wireless_capture" name="test_handshake_detect" time="0.120"/>
  </testsuite>
</testsuites>"""

        result = parse_junit_xml(xml)
        assert result["pass_count"] == 3
        assert result["fail_count"] == 0
        assert result["skip_count"] == 0
        assert result["total"] == 3
        assert len(result["tests"]) == 3

    def test_parses_failures_and_skips(self, tmp_path):
        """Parses JUnit XML with failures and skipped tests."""
        from scripts.test_report import parse_junit_xml

        xml = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="1" failures="1" skipped="2" tests="5" time="3.456">
    <testcase classname="tests.test_foo" name="test_pass" time="0.010"/>
    <testcase classname="tests.test_foo" name="test_fail" time="0.020">
      <failure message="AssertionError">assert 1 == 2</failure>
    </testcase>
    <testcase classname="tests.test_foo" name="test_error" time="0.005">
      <error message="ValueError">bad thing happened</error>
    </testcase>
    <testcase classname="tests.test_bar" name="test_skip" time="0.001">
      <skipped message="no hardware"/>
    </testcase>
    <testcase classname="tests.test_bar" name="test_skip2" time="0.000">
      <skipped message="no hardware"/>
    </testcase>
  </testsuite>
</testsuites>"""

        result = parse_junit_xml(xml)
        assert result["pass_count"] == 1
        assert result["fail_count"] == 2  # failure + error
        assert result["skip_count"] == 2
        assert result["total"] == 5

    def test_empty_results(self):
        """Handles empty JUnit XML gracefully."""
        from scripts.test_report import parse_junit_xml

        xml = """<?xml version="1.0"?><testsuites>
  <testsuite name="pytest" errors="0" failures="0" skipped="0" tests="0" time="0.0"/>
</testsuites>"""

        result = parse_junit_xml(xml)
        assert result["total"] == 0
        assert result["pass_count"] == 0


# ── Test: detect_category() ──


class TestDetectCategory:
    """Tests for detecting wired vs wireless from test paths."""

    def test_detects_wireless(self):
        """test_wireless_*.py paths are wireless."""
        from scripts.test_report import detect_category

        tests = [
            {"path": "tests/test_wireless_scan.py"},
            {"path": "tests/test_wireless_capture.py"},
            {"path": "tests/test_wireless_pmkid.py"},
        ]
        assert detect_category(tests) == "wireless"

    def test_detects_wired(self):
        """Non-wireless paths are wired."""
        from scripts.test_report import detect_category

        tests = [
            {"path": "tests/test_topology.py"},
            {"path": "tests/test_uat_wired.py"},
        ]
        assert detect_category(tests) == "wired"

    def test_mixed_defaults_to_wired(self):
        """Mixed paths default to wired."""
        from scripts.test_report import detect_category

        tests = [
            {"path": "tests/test_wireless_scan.py"},
            {"path": "tests/test_topology.py"},
        ]
        assert detect_category(tests) == "wired"


# ── Test: save_report() ──


class TestSaveReport:
    """Tests for saving results to outputs/reports/."""

    def test_creates_report_directory(self, tmp_path):
        """Creates the timestamped report directory and files."""
        from scripts.test_report import save_report

        result = {
            "pass_count": 3, "fail_count": 1, "skip_count": 0, "total": 4,
            "duration": 1.5,
            "tests": [
                {"name": "test_foo", "status": "passed", "duration": 0.01, "path": "tests/test_foo.py"},
                {"name": "test_bar", "status": "failed", "duration": 0.02, "path": "tests/test_bar.py",
                 "message": "assert False"},
                {"name": "test_baz", "status": "passed", "duration": 0.01, "path": "tests/test_baz.py"},
                {"name": "test_qux", "status": "passed", "duration": 0.01, "path": "tests/test_qux.py"},
            ],
        }

        timestamp = "2026-07-13-17-52-00"
        save_report(result, "wireless", timestamp, tmp_path)

        report_dir = tmp_path / "wireless-2026-07-13-17-52-00"
        assert report_dir.exists()

        results_file = report_dir / "results.json"
        assert results_file.exists()
        data = json.loads(results_file.read_text())
        assert data["pass_count"] == 3
        assert data["category"] == "wireless"
        assert data["timestamp"] == timestamp

        summary_file = report_dir / "summary.txt"
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "4 tests" in content
        assert "3 passed" in content
        assert "1 failed" in content

    def test_parent_dir_created(self, tmp_path):
        """outputs/reports/ parent directory is created if missing."""
        from scripts.test_report import save_report

        save_report({"pass_count": 0, "fail_count": 0, "skip_count": 0, "total": 0, "tests": []},
                    "wired", "2026-07-13-12-00-00", tmp_path / "deep" / "nested")

        assert (tmp_path / "deep" / "nested" / "wired-2026-07-13-12-00-00").exists()

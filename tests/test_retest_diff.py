"""Tests for retest-diff.py — baseline vs retest delta comparison."""
import importlib.util
import json
from pathlib import Path

import pytest

# Load retest_diff module directly by file path (avoid sys.path issues during pytest collection)
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "skills" / "site-assessment-pipeline" / "scripts"
_retest_diff_path = SCRIPTS_DIR / "retest-diff.py"
_spec = importlib.util.spec_from_file_location("retest_diff", str(_retest_diff_path))
_retest_diff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_retest_diff)

compare = _retest_diff.compare
make_key = _retest_diff.make_key
_sev_rank = _retest_diff._sev_rank

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# make_key
# ---------------------------------------------------------------------------
class TestMakeKey:
    def test_cve_key_when_cve_present(self):
        finding = {"host": "10.0.0.1", "port": 443, "cve": "CVE-2021-23017", "service": "nginx"}
        assert make_key(finding) == "10.0.0.1:443:CVE-2021-23017"

    def test_service_fallback_when_no_cve(self):
        finding = {"host": "10.0.0.1", "port": 80, "cve": "", "service": "http"}
        assert make_key(finding) == "10.0.0.1:80:http"

    def test_service_fallback_when_cve_missing_key(self):
        finding = {"host": "10.0.0.1", "port": 22, "service": "ssh"}
        assert make_key(finding) == "10.0.0.1:22:ssh"

    def test_missing_host_defaults_empty(self):
        finding = {"port": 443, "cve": "CVE-2021-9999"}
        assert make_key(finding) == ":443:CVE-2021-9999"

    def test_empty_input_all_defaults(self):
        assert make_key({}) == "::"


# ---------------------------------------------------------------------------
# _sev_rank
# ---------------------------------------------------------------------------
class TestSevRank:
    def test_ordering_critical_is_most_severe(self):
        assert _sev_rank("critical") < _sev_rank("high")
        assert _sev_rank("high") < _sev_rank("medium")
        assert _sev_rank("medium") < _sev_rank("low")
        assert _sev_rank("low") < _sev_rank("info")

    def test_unknown_severity_returns_99(self):
        assert _sev_rank("bogus") == 99
        assert _sev_rank("") == 99


# ---------------------------------------------------------------------------
# compare (the core delta)
# ---------------------------------------------------------------------------
class TestCompare:
    def test_baseline_vs_retest_counts(self):
        """Verify the expected classification counts with real fixtures."""
        baseline = _load("baseline-findings.json")   # 10 findings
        retest = _load("retest-findings.json")        # 7 findings

        delta = compare(baseline, retest)

        # Fixed: FIND-002, FIND-004, FIND-007, FIND-010  (4 that are gone)
        assert delta["summary"]["fixed_count"] == 4
        # Still open: FIND-001, FIND-003, FIND-005, FIND-006, FIND-008, FIND-009  (6)
        assert delta["summary"]["still_open_count"] == 6
        # New: NEW-001 (1)
        assert delta["summary"]["new_count"] == 1
        # Regression: 0 (no severity increased)
        assert delta["summary"]["regression_count"] == 0

        assert delta["baseline_total"] == 10
        assert delta["retest_total"] == 7

        # Verify specific fixed IDs
        fixed_ids = {f["id"] for f in delta["fixed"]}
        assert fixed_ids == {"FIND-002", "FIND-004", "FIND-007", "FIND-010"}

        # Verify new IDs
        new_ids = {f["id"] for f in delta["new"]}
        assert new_ids == {"NEW-001"}

        # Still-open IDs
        still_ids = {f["id"] for f in delta["still_open"]}
        assert still_ids == {"FIND-001", "FIND-003", "FIND-005", "FIND-006", "FIND-008", "FIND-009"}

    def test_empty_baseline_all_new(self):
        """Empty baseline → every retest finding is NEW."""
        baseline = []
        retest = _load("retest-findings.json")

        delta = compare(baseline, retest)

        assert delta["summary"]["fixed_count"] == 0
        assert delta["summary"]["still_open_count"] == 0
        assert delta["summary"]["new_count"] == len(retest)
        assert delta["summary"]["regression_count"] == 0

    def test_empty_retest_all_fixed(self):
        """Empty retest → every baseline finding is FIXED."""
        baseline = _load("baseline-findings.json")
        retest = []

        delta = compare(baseline, retest)

        assert delta["summary"]["fixed_count"] == len(baseline)
        assert delta["summary"]["still_open_count"] == 0
        assert delta["summary"]["new_count"] == 0
        assert delta["summary"]["regression_count"] == 0

    def test_identical_scans_all_still_open(self):
        """Same findings in both → all STILL_OPEN, nothing else."""
        baseline = _load("baseline-findings.json")
        retest = _load("baseline-findings.json")  # identical

        delta = compare(baseline, retest)

        assert delta["summary"]["fixed_count"] == 0
        assert delta["summary"]["still_open_count"] == len(baseline)
        assert delta["summary"]["new_count"] == 0
        assert delta["summary"]["regression_count"] == 0

    def test_regression_detection_severity_got_worse(self):
        """When severity increases in retest, the finding is marked REGRESSION."""
        baseline = [
            {
                "id": "FIND-001",
                "title": "Weak cipher",
                "host": "10.0.0.1",
                "port": 443,
                "service": "nginx",
                "cve": "CVE-2020-0001",
                "severity": "medium",
            }
        ]
        retest = [
            {
                "id": "FIND-001",
                "title": "Weak cipher",
                "host": "10.0.0.1",
                "port": 443,
                "service": "nginx",
                "cve": "CVE-2020-0001",
                "severity": "critical",
            }
        ]

        delta = compare(baseline, retest)

        assert delta["summary"]["regression_count"] == 1
        assert delta["summary"]["still_open_count"] == 0
        assert delta["summary"]["fixed_count"] == 0
        assert delta["summary"]["new_count"] == 0

        reg = delta["regression"][0]
        assert reg["id"] == "FIND-001"
        assert reg["retest_status"] == "REGRESSION"
        assert reg["old_severity"] == "medium"
        assert reg["severity"] == "critical"

    def test_no_regression_when_severity_improved(self):
        """When severity decreases (fixed/improved), still STILL_OPEN, not REGRESSION."""
        baseline = [
            {
                "id": "FIND-001",
                "title": "Outdated service",
                "host": "10.0.0.1",
                "port": 80,
                "service": "http",
                "cve": "CVE-2020-0001",
                "severity": "critical",
            }
        ]
        retest = [
            {
                "id": "FIND-001",
                "title": "Outdated service",
                "host": "10.0.0.1",
                "port": 80,
                "service": "http",
                "cve": "CVE-2020-0001",
                "severity": "low",
            }
        ]

        delta = compare(baseline, retest)

        assert delta["summary"]["regression_count"] == 0
        assert delta["summary"]["still_open_count"] == 1

    def test_still_open_retains_retest_status_field(self):
        baseline = _load("baseline-findings.json")
        retest = _load("retest-findings.json")

        delta = compare(baseline, retest)
        for f in delta["still_open"]:
            assert f["retest_status"] == "STILL_OPEN"

    def test_fixed_retains_retest_status_field(self):
        baseline = _load("baseline-findings.json")
        retest = []

        delta = compare(baseline, retest)
        for f in delta["fixed"]:
            assert f["retest_status"] == "FIXED"

    def test_new_retains_retest_status_field(self):
        baseline = []
        retest = _load("retest-findings.json")

        delta = compare(baseline, retest)
        for f in delta["new"]:
            assert f["retest_status"] == "NEW"

    def test_make_key_matches_across_fixtures(self):
        """Ensure make_key correctly links findings between baseline and retest."""
        baseline = _load("baseline-findings.json")
        retest = _load("retest-findings.json")

        # FIND-001 is in both — keys must match
        b_f1 = next(f for f in baseline if f["id"] == "FIND-001")
        r_f1 = next(f for f in retest if f["id"] == "FIND-001")
        assert make_key(b_f1) == make_key(r_f1)

        # FIND-002 is in baseline only
        b_f2 = next(f for f in baseline if f["id"] == "FIND-002")
        assert make_key(b_f2) not in {make_key(f) for f in retest}

        # NEW-001 is in retest only
        r_new = next(f for f in retest if f["id"] == "NEW-001")
        assert make_key(r_new) not in {make_key(f) for f in baseline}

    def test_delta_includes_scan_date(self):
        baseline = [_load("baseline-findings.json")[0]]
        retest = baseline.copy()

        delta = compare(baseline, retest)
        assert "scan_date" in delta
        assert isinstance(delta["scan_date"], str)

"""Tests for scripts/wireless_assess.py — target assessment from managed-mode scans."""

import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add project root so we can import the script module
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.wireless_assess import (
    find_latest,
    get_associated_bssid,
    assess_targets,
    print_assessment_report,
)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for test assertion matching."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)

# ── Sample data ──

SAMPLE_TARGETS = [
    {"ssid": "TESTAP", "bssid": "E2:62:79:B3:48:83",
     "channel": 36, "encryption": "WPA3-SAE", "signal_dbm": -66},
    {"ssid": "TESTAP_EXT", "bssid": "D8:32:14:0C:5B:64",
     "channel": 6, "encryption": "WPA2-PSK", "signal_dbm": -30},
    {"ssid": "OPTUS_0593B0N", "bssid": "8C:83:94:05:93:B3",
     "channel": 11, "encryption": "WPA2-PSK", "signal_dbm": -78},
]

SAMPLE_CURRENT_APS = [
    {"ssid": "TESTAP", "bssid": "E2:62:79:B3:48:83",
     "channel": 36, "encryption": "WPA3-SAE", "signal_dbm": -68},
    {"ssid": "TESTAP_EXT", "bssid": "D8:32:14:0C:5B:64",
     "channel": 6, "encryption": "WPA2-PSK", "signal_dbm": -32},
    {"ssid": "TESTAP", "bssid": "E2:62:79:B3:48:82",
     "channel": 6, "encryption": "WPA3-SAE", "signal_dbm": -52},
    {"ssid": "TESTAP-LEGACY", "bssid": "E6:62:79:B3:48:83",
     "channel": 36, "encryption": "WPA2-PSK", "signal_dbm": -68},
    {"ssid": "Dandan", "bssid": "0C:EF:15:DF:D2:6B",
     "channel": 1, "encryption": "WPA2-PSK", "signal_dbm": -85},
]

SAMPLE_TARGETS_FILE = {
    "selection_metadata": {
        "timestamp": "20260706T103000Z",
        "source_scan": "wireless-aps-test.json",
        "selection_mode": "auto",
        "total_available": 5,
        "total_selected": 3,
    },
    "targets": SAMPLE_TARGETS,
}


# ── find_latest() ──


class TestFindLatest:
    def test_no_output_dir(self, tmp_path, monkeypatch):
        """Returns None when dir doesn't exist."""
        monkeypatch.setattr("scripts.wireless_assess.OUTPUT_DIR",
                            tmp_path / "nope")
        assert find_latest("targets-*.json", "targets") is None

    def test_finds_latest(self, tmp_path, monkeypatch):
        """Returns most recent matching file."""
        monkeypatch.setattr("scripts.wireless_assess.OUTPUT_DIR", tmp_path)
        f1 = tmp_path / "targets-20260706T100000Z.json"
        f2 = tmp_path / "targets-20260706T110000Z.json"
        f1.write_text("{}")
        f2.write_text("{}")
        result = find_latest("targets-*.json", "targets")
        assert result == f2

    def test_no_match(self, tmp_path, monkeypatch):
        """Returns None when no files match pattern."""
        monkeypatch.setattr("scripts.wireless_assess.OUTPUT_DIR", tmp_path)
        (tmp_path / "other.txt").write_text("")
        assert find_latest("targets-*.json", "targets") is None


# ── get_associated_bssid() ──


class TestGetAssociatedBSSID:
    def test_returns_bssid(self):
        """Parses 'Connected to' line from iw dev link output."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = (
                "Connected to e2:62:79:b3:48:83 (on wlan0)\n"
                "\tSSID: TESTAP\n"
                "\tfreq: 5180\n"
            )
            mock_run.return_value.returncode = 0
            result = get_associated_bssid("wlan0")
            assert result == "E2:62:79:B3:48:83"

    def test_not_connected(self):
        """Returns None when not connected."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "Not connected.\n"
            mock_run.return_value.returncode = 0
            assert get_associated_bssid("wlan0") is None

    def test_failure_returns_none(self):
        """Returns None on subprocess failure."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            assert get_associated_bssid("wlan0") is None


# ── assess_targets() ──


class TestAssessTargets:
    def test_visible_targets_marked(self):
        """Targets found in current scan are marked visible."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS, iface="wlan0")
        visibles = [t for t in result["targets"] if t["assessment"]["visible"]]
        assert len(visibles) == 2  # TESTAP and TESTAP_EXT

    def test_invisible_targets_marked(self):
        """Targets not in current scan are marked invisible."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS)
        invisible = [t for t in result["targets"] if not t["assessment"]["visible"]]
        assert len(invisible) == 1  # OPTUS_0593B0N

    def test_signal_change_calculated(self):
        """Signal difference between original and current is calculated."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS)
        for t in result["targets"]:
            if t["assessment"]["visible"]:
                assert "signal_change" in t["assessment"]
                # TESTAP went from -66 to -68 = -2
                if t["bssid"] == "E2:62:79:B3:48:83":
                    assert t["assessment"]["signal_change"] == -2
                # TESTAP_EXT went from -30 to -32 = -2
                if t["bssid"] == "D8:32:14:0C:5B:64":
                    assert t["assessment"]["signal_change"] == -2

    def test_channel_match(self):
        """Channel match is True when channels agree."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS)
        for t in result["targets"]:
            if t["assessment"]["visible"]:
                assert t["assessment"]["channel_match"] is True

    def test_encryption_match(self):
        """Encryption match is True when types agree."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS)
        for t in result["targets"]:
            if t["assessment"]["visible"]:
                assert t["assessment"]["encryption_match"] is True

    def test_channel_mismatch_detected(self):
        """Channel mismatch is detected when channels differ."""
        changed_aps = [
            {**SAMPLE_CURRENT_APS[0], "channel": 40},  # was 36
            *SAMPLE_CURRENT_APS[1:],
        ]
        result = assess_targets(SAMPLE_TARGETS, changed_aps)
        for t in result["targets"]:
            if t["bssid"] == "E2:62:79:B3:48:83":
                assert t["assessment"]["channel_match"] is False

    def test_encryption_mismatch_detected(self):
        """Encryption mismatch is detected."""
        changed_aps = [
            {**SAMPLE_CURRENT_APS[0], "encryption": "WPA2-PSK"},  # was WPA3-SAE
            *SAMPLE_CURRENT_APS[1:],
        ]
        result = assess_targets(SAMPLE_TARGETS, changed_aps)
        for t in result["targets"]:
            if t["bssid"] == "E2:62:79:B3:48:83":
                assert t["assessment"]["encryption_match"] is False

    def test_associated_flag(self):
        """Associated flag is True when BSSID matches current association."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS, iface="wlan0")
        for t in result["targets"]:
            if t["bssid"] == "E2:62:79:B3:48:83":
                assert t["assessment"]["associated"] is True
            else:
                assert t["assessment"]["associated"] is False

    def test_empty_targets(self):
        """Empty targets list returns zero counts."""
        result = assess_targets([], SAMPLE_CURRENT_APS)
        assert result["total_targets"] == 0
        assert result["targets_visible"] == 0

    def test_empty_scan(self):
        """Empty scan means nothing is visible."""
        result = assess_targets(SAMPLE_TARGETS, [])
        assert result["targets_visible"] == 0
        assert result["targets_invisible"] == 3


# ── print_assessment_report() ──


class TestPrintAssessment:
    def test_empty_targets(self, capsys):
        """Prints a message with no targets."""
        result = {"total_targets": 0, "targets_visible": 0,
                  "targets_invisible": 0, "associated_count": 0,
                  "targets": []}
        print_assessment_report(result)
        out = strip_ansi(capsys.readouterr().out)
        assert "No targets" in out

    def test_reports_visible_and_invisible(self, capsys):
        """Prints visible/invisible counts correctly."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS)
        print_assessment_report(result)
        out = strip_ansi(capsys.readouterr().out)
        assert "2 visible" in out
        assert "1 invisible" in out

    def test_shows_ssid_and_bssid(self, capsys):
        """Per-target output shows SSID and BSSID."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS)
        print_assessment_report(result)
        out = strip_ansi(capsys.readouterr().out)
        assert "TESTAP" in out
        assert "E2:62:79:B3:48:83" in out

    def test_signal_change_displayed(self, capsys):
        """Signal change shows in output for visible targets."""
        result = assess_targets(SAMPLE_TARGETS, SAMPLE_CURRENT_APS)
        print_assessment_report(result)
        out = strip_ansi(capsys.readouterr().out)
        assert "Signal:" in out
        assert "dBm" in out


# ── CLI integration ──


class TestCLIIntegration:
    """Test the assess script runs via its CLI entry point."""

    def _make_targets_file(self, tmp_path) -> str:
        """Create a temporary targets file and return its path."""
        tf = tmp_path / "targets.json"
        tf.write_text(json.dumps(SAMPLE_TARGETS_FILE))
        return str(tf)

    def test_no_targets_file_exits(self):
        """Running without targets file prints error and exits."""
        from scripts.wireless_assess import main
        with (
            patch("scripts.wireless_assess.find_latest", return_value=None),
            patch.object(sys, "argv", ["wireless_assess.py"]),
        ):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_runs_with_file(self, tmp_path):
        """Assess runs with a valid targets file and produces output."""
        from scripts.wireless_assess import main
        tf = self._make_targets_file(tmp_path)
        output_dir = tmp_path / "outputs" / "wireless"
        output_dir.mkdir(parents=True)

        test_args = [
            "--targets-file", tf,
            "--no-scan",
            "--output-dir", str(output_dir),
        ]
        # Need to prevent real iw scan calls — mock detect_interfaces
        # to return something valid so it doesn't fail early
        with (
            patch.object(sys, "argv", ["wireless_assess.py"] + test_args),
            patch("scripts.wireless_assess.require_external_adapter",
                  return_value={"name": "wlan0"}),
        ):
            import builtins
            original_print = builtins.print
            try:
                main()
            finally:
                builtins.print = original_print

            assessment_files = list(output_dir.glob("assessment-*.json"))
            assert len(assessment_files) == 1
            data = json.loads(assessment_files[0].read_text())
            assert data["assessment_metadata"]["total_targets"] == 3
            assert "targets" in data

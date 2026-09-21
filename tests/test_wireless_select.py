"""Tests for scripts/wireless_select.py — target selection from scan results."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add project root so we can import the script module
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.wireless_select import (
    find_latest_scan,
    load_scan,
    parse_selection_input,
    auto_select,
    print_ap_table,
    OUTPUT_DIR,
)

# ── Sample data ──

SAMPLE_APS = [
    {"ssid": "TESTAP", "display_ssid": "TESTAP", "bssid": "E2:62:79:B3:48:83",
     "channel": 36, "encryption": "WPA3-SAE", "signal_dbm": -66},
    {"ssid": "TESTAP", "display_ssid": "TESTAP", "bssid": "E2:62:79:B3:48:82",
     "channel": 6, "encryption": "WPA3-SAE", "signal_dbm": -50},
    {"ssid": "TESTAP-LEGACY", "display_ssid": "TESTAP-LEGACY", "bssid": "E6:62:79:B3:48:83",
     "channel": 36, "encryption": "WPA2-PSK", "signal_dbm": -66},
    {"ssid": "TESTAP_EXT", "display_ssid": "TESTAP_EXT", "bssid": "D8:32:14:0C:5B:64",
     "channel": 6, "encryption": "WPA2-PSK", "signal_dbm": -30},
    {"ssid": "OPTUS_0593B0N", "display_ssid": "OPTUS_0593B0N", "bssid": "8C:83:94:05:93:B3",
     "channel": 11, "encryption": "WPA2-PSK", "signal_dbm": -78},
]

SAMPLE_SCAN = {
    "scan_metadata": {
        "timestamp": "20260706T103000Z",
        "interface": "wlan0",
        "tool": "iw scan",
        "mode": "managed",
        "band": "both",
        "duration_seconds": 10,
    },
    "access_points": SAMPLE_APS,
    "total_aps": len(SAMPLE_APS),
}


# ── find_latest_scan() ──


class TestFindLatestScan:
    def test_no_output_dir(self, tmp_path, monkeypatch):
        """Returns None when OUTPUT_DIR doesn't exist."""
        monkeypatch.setattr(
            "scripts.wireless_select.OUTPUT_DIR",
            tmp_path / "does-not-exist",
        )
        assert find_latest_scan() is None

    def test_no_files(self, tmp_path, monkeypatch):
        """Returns None when directory exists but has no scan files."""
        monkeypatch.setattr("scripts.wireless_select.OUTPUT_DIR", tmp_path)
        assert find_latest_scan() is None

    def test_finds_latest(self, tmp_path, monkeypatch):
        """Returns the most recent wireless-aps-*.json file."""
        monkeypatch.setattr("scripts.wireless_select.OUTPUT_DIR", tmp_path)
        f1 = tmp_path / "wireless-aps-20260706T100000Z.json"
        f2 = tmp_path / "wireless-aps-20260706T110000Z.json"
        f1.write_text("{}")
        f2.write_text("{}")
        result = find_latest_scan()
        assert result == f2

    def test_ignores_other_files(self, tmp_path, monkeypatch):
        """Ignores non-wireless-aps files in the directory."""
        monkeypatch.setattr("scripts.wireless_select.OUTPUT_DIR", tmp_path)
        # Create some non-wireless-aps files
        (tmp_path / "targets-20260706T100000Z.json").write_text("{}")
        (tmp_path / "other.txt").write_text("")
        assert find_latest_scan() is None


# ── load_scan() ──


class TestLoadScan:
    def test_loads_valid_file(self, tmp_path):
        """Returns parsed dict from a valid scan JSON."""
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(SAMPLE_SCAN))
        data = load_scan(f)
        assert data["total_aps"] == 5
        assert len(data["access_points"]) == 5

    def test_missing_access_points_key(self, tmp_path):
        """Exits with sys.exit(1) when 'access_points' key is missing."""
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"foo": "bar"}))
        with pytest.raises(SystemExit):
            load_scan(f)


# ── parse_selection_input() ──


class TestParseSelectionInput:
    def test_single_number(self):
        """'3' returns [2] (0-based)."""
        assert parse_selection_input("3", 10) == [2]

    def test_range(self):
        """'3-5' returns [2, 3, 4]."""
        assert parse_selection_input("3-5", 10) == [2, 3, 4]

    def test_comma_separated(self):
        """'1,3,5' returns [0, 2, 4]."""
        assert parse_selection_input("1,3,5", 10) == [0, 2, 4]

    def test_combo(self):
        """'1,3-5,7' returns [0, 2, 3, 4, 6]."""
        assert parse_selection_input("1,3-5,7", 10) == [0, 2, 3, 4, 6]

    def test_out_of_bounds_clamped(self):
        """Indices beyond max_idx are silently dropped."""
        assert parse_selection_input("99", 5) == []

    def test_empty_string(self):
        """Empty string returns empty list."""
        assert parse_selection_input("", 5) == []

    def test_invalid_format(self):
        """Garbage input returns empty list."""
        assert parse_selection_input("abc", 5) == []

    def test_reversed_range(self):
        """'5-3' returns [2, 3, 4] (covered range)."""
        result = parse_selection_input("5-3", 10)
        assert result == [2, 3, 4]

    def test_first_item(self):
        """'1' returns [0]."""
        assert parse_selection_input("1", 5) == [0]

    def test_last_item(self):
        """'5' returns [4]."""
        assert parse_selection_input("5", 5) == [4]

    def test_whitespace_handling(self):
        """' 1 , 3-5 ' returns [0, 2, 3, 4]."""
        assert parse_selection_input(" 1 , 3-5 ", 10) == [0, 2, 3, 4]


# ── auto_select() ──


class TestAutoSelect:
    def test_selects_by_signal_strength(self):
        """Returns strongest APs first."""
        result = auto_select(SAMPLE_APS, max_count=3)
        assert len(result) == 3
        # Strongest signals first
        signals = [a["signal_dbm"] for a in result]
        assert signals == sorted(signals, reverse=True)

    def test_respects_max_count(self):
        """Does not return more than max_count items."""
        result = auto_select(SAMPLE_APS, max_count=2)
        assert len(result) == 2

    def test_prefers_unique_ssids(self):
        """Prefers one BSSID per SSID before adding duplicates."""
        result = auto_select(SAMPLE_APS, max_count=10)
        ssids = [a["ssid"] for a in result]
        # Sample has 4 unique SSIDs — first 4 should all be unique
        first_four = ssids[:4]
        assert len(set(first_four)) == len(first_four), (
            f"Expected all unique SSIDs in first {len(first_four)}: {first_four}"
        )

    def test_empty_list(self):
        """Empty input returns empty list."""
        assert auto_select([], max_count=5) == []

    def test_less_than_max(self):
        """When fewer APs than max_count, returns all."""
        result = auto_select(SAMPLE_APS, max_count=100)
        assert len(result) == len(SAMPLE_APS)

    def test_strongest_first_order(self):
        """The single strongest AP should be first."""
        result = auto_select(SAMPLE_APS, max_count=1)
        assert result[0]["signal_dbm"] == -30  # TESTAP_EXT

    def test_signals_none_handled(self):
        """APs with None signal are sorted last."""
        aps_with_none = SAMPLE_APS + [
            {"ssid": "Ghost", "display_ssid": "Ghost", "bssid": "AA:BB:CC:DD:EE:FF",
             "channel": 1, "encryption": "Open", "signal_dbm": None},
        ]
        result = auto_select(aps_with_none, max_count=10)
        # All known-signal APs come before the None-signal one
        signals = [a.get("signal_dbm") for a in result if a["ssid"] != "Ghost"]
        assert all(s is not None for s in signals)


# ── print_ap_table() ──


class TestPrintAPTable:
    def test_empty_aps(self, capsys):
        """Prints a message and returns cleanly when AP list is empty."""
        print_ap_table([], show_index=True)
        captured = capsys.readouterr()
        assert "No access points" in captured.out

    def test_with_data(self, capsys):
        """Prints a table without crashing when data is present."""
        print_ap_table(SAMPLE_APS, show_index=True)
        captured = capsys.readouterr()
        assert "TESTAP" in captured.out
        assert "WPA3-SAE" in captured.out

    def test_no_index(self, capsys):
        """Prints a table without index column."""
        print_ap_table(SAMPLE_APS, show_index=False)
        captured = capsys.readouterr()
        assert "TESTAP" in captured.out


# ── CLI integration ──


class TestCLIIntegration:
    """Test the script runs via its CLI entry point."""

    def _make_scan_file(self, tmp_path) -> str:
        """Create a temporary scan file and return its path."""
        scan_file = tmp_path / "scan.json"
        scan_file.write_text(json.dumps(SAMPLE_SCAN))
        return str(scan_file)

    def test_list_mode(self, tmp_path):
        """--list exits cleanly and shows AP table."""
        from scripts.wireless_select import main
        scan_path = self._make_scan_file(tmp_path)
        test_args = ["--scan-file", scan_path, "--list"]
        with patch.object(sys, "argv", ["wireless_select.py"] + test_args):
            import builtins
            spy = []
            original_print = builtins.print

            def capture_print(*args, **kwargs):
                spy.append(args)
                original_print(*args, **kwargs)
            builtins.print = capture_print

            # --list returns cleanly, no sys.exit
            main()
            builtins.print = original_print

            output = " ".join(str(a) for a in spy)
            assert "TESTAP" in output

    def test_auto_mode_creates_file(self, tmp_path):
        """--auto saves a targets file."""
        from scripts.wireless_select import main
        scan_path = self._make_scan_file(tmp_path)
        output_dir = tmp_path / "outputs" / "wireless"
        output_dir.mkdir(parents=True)
        test_args = [
            "--scan-file", scan_path,
            "--auto", "--max", "3",
            "--output-dir", str(output_dir),
        ]
        with patch.object(sys, "argv", ["wireless_select.py"] + test_args):
            import builtins
            original_print = builtins.print
            main()
            builtins.print = original_print

            target_files = list(output_dir.glob("targets-*.json"))
            assert len(target_files) == 1
            with open(target_files[0]) as f:
                data = json.load(f)
            assert data["selection_metadata"]["total_selected"] == 3
            assert len(data["targets"]) == 3

    def test_force_alias_for_auto(self, tmp_path):
        """--force is an alias for --auto."""
        from scripts.wireless_select import main
        scan_path = self._make_scan_file(tmp_path)
        output_dir = tmp_path / "outputs2" / "wireless"
        output_dir.mkdir(parents=True)
        test_args = [
            "--scan-file", scan_path,
            "--force",
            "--output-dir", str(output_dir),
        ]
        with patch.object(sys, "argv", ["wireless_select.py"] + test_args):
            import builtins
            original_print = builtins.print
            main()
            builtins.print = original_print

            target_files = list(output_dir.glob("targets-*.json"))
            assert len(target_files) == 1
            data = json.loads(target_files[0].read_text())
            assert data["selection_metadata"]["selection_mode"] == "auto"

    def test_no_scan_file_exits(self):
        """Running without a scan file prints error and exits."""
        from scripts.wireless_select import main
        with (
            patch("scripts.wireless_select.find_latest_scan", return_value=None),
            patch.object(sys, "argv", ["wireless_select.py"]),
        ):
            import builtins
            spy = []
            original_print = builtins.print

            def capture_print(*args, **kwargs):
                spy.append(args)
                original_print(*args, **kwargs)
            builtins.print = capture_print

            try:
                with pytest.raises(SystemExit) as exc:
                    main()
                assert exc.value.code == 1
            finally:
                builtins.print = original_print

            output = " ".join(str(a) for a in spy)
            assert "No scan results found" in output

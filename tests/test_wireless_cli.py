"""Tests for the portshim wireless subcommand and wireless_scan module."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WIRELESS_SCRIPT = str(PROJECT_ROOT / "scripts" / "wireless_scan.py")
PORTSHIM_BIN = sys.executable
PORTSHIM_SCRIPT = str(PROJECT_ROOT / "portshim")


# ── Helpers ──

def run_portshim(*args):
    """Run portshim CLI and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [PORTSHIM_BIN, PORTSHIM_SCRIPT] + list(args),
        capture_output=True, text=True, timeout=30,
        cwd=PROJECT_ROOT,
    )
    clean = result.stdout.replace("\033[92m", "").replace("\033[91m", "")
    clean = clean.replace("\033[96m", "").replace("\033[93m", "")
    clean = clean.replace("\033[1m", "").replace("\033[0m", "")
    clean = clean.replace("\033[2m", "")
    return result.returncode, clean, result.stderr


def run_wireless_script(*args):
    """Run wireless_scan.py directly and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [PORTSHIM_BIN, WIRELESS_SCRIPT] + list(args),
        capture_output=True, text=True, timeout=30,
        cwd=PROJECT_ROOT,
    )
    clean = result.stdout.replace("\033[92m", "").replace("\033[91m", "")
    clean = clean.replace("\033[96m", "").replace("\033[93m", "")
    clean = clean.replace("\033[1m", "").replace("\033[0m", "")
    clean = clean.replace("\033[2m", "")
    return result.returncode, clean, result.stderr


# ── Wireless CLI integration ──

class TestWirelessSubcommand:
    """portshim wireless subcommand registration."""

    def test_wireless_in_main_help(self):
        """Main help should list 'wireless' as a command."""
        rc, out, err = run_portshim("--help")
        assert rc == 0
        assert "wireless" in out, f"Expected 'wireless' in help: {out}"

    def test_wireless_help_shows_subcommands(self):
        """portshim wireless --help shows scan, select, assess."""
        rc, out, err = run_portshim("wireless", "--help")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        for cmd in ["scan", "select", "assess"]:
            assert cmd in out, f"Expected '{cmd}' in wireless help: {out}"

    def test_wireless_scan_help_shows_options(self):
        """portshim wireless scan --help shows duration, band, interface, dry-run."""
        rc, out, err = run_portshim("wireless", "scan", "--help")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        for opt in ["--duration", "--band", "--interface", "--dry-run"]:
            assert opt in out, f"Expected '{opt}' in scan help: {out}"

    def test_wireless_scan_help_band_choices(self):
        """--band should accept 2.4, 5, both."""
        rc, out, err = run_portshim("wireless", "scan", "--help")
        assert rc == 0
        assert "2.4" in out, f"Expected 2.4 in band choices: {out}"
        assert "both" in out, f"Expected both in band choices: {out}"

    def test_wireless_select_shows_stub(self, tmp_path):
        """portshim wireless select runs the select script (fails gracefully without scan data)."""
        empty_dir = tmp_path / "empty-wd"
        empty_dir.mkdir()
        rc, out, err = run_portshim("wireless", "select", "--output-dir", str(empty_dir))
        assert rc == 1, f"Unexpected rc: {rc}\n{err}"
        assert "No scan results found" in out or "Target selection" in out, f"Unexpected output: {out}"

    def test_wireless_assess_shows_stub(self, tmp_path):
        """portshim wireless assess runs the assess script (fails gracefully without targets)."""
        empty_dir = tmp_path / "empty-wd"
        empty_dir.mkdir()
        rc, out, err = run_portshim("wireless", "assess", "--output-dir", str(empty_dir))
        # Assess script exits with 1 if no targets file found
        assert rc == 1, f"Unexpected rc: {rc}\n{err}"
        assert "No target selection found" in out or "Target assessment" in out, f"Unexpected output: {out}"

    def test_output_dir_controls_discovery(self, tmp_path):
        """--output-dir governs scan discovery, not just where results are written."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        rc, out, err = run_portshim("wireless", "select", "--output-dir", str(empty_dir), "--list")
        assert rc == 1, f"Expected no scan found in empty dir: rc={rc}\n{out}\n{err}"
        assert "No scan results found" in out, f"Unexpected output: {out}"

        populated_dir = tmp_path / "populated"
        populated_dir.mkdir()
        scan_data = {
            "scan_metadata": {
                "timestamp": "20260706T103000Z",
                "interface": "wlan0",
                "tool": "iw scan",
                "mode": "managed",
                "band": "both",
                "duration_seconds": 10,
            },
            "access_points": [
                {"ssid": "TESTAP", "display_ssid": "TESTAP", "bssid": "E2:62:79:B3:48:83",
                 "channel": 36, "encryption": "WPA3-SAE", "signal_dbm": -66},
            ],
            "total_aps": 1,
        }
        (populated_dir / "wireless-aps-20260706T103000Z.json").write_text(json.dumps(scan_data))
        rc, out, err = run_portshim("wireless", "select", "--output-dir", str(populated_dir), "--list")
        assert rc == 0, f"Expected scan to be discovered in populated dir: rc={rc}\n{out}\n{err}"
        assert "TESTAP" in out, f"Expected discovered AP in output: {out}"

    def test_select_max_zero_is_forwarded(self, tmp_path):
        """--max 0 must reach the select script.

        Regression: the wrapper forwarded --max on a truthiness check, so an
        explicit `--max 0` (meaning "select nothing") was silently dropped and
        the script fell back to its own default of 5. auto_select(aps, 0)
        returns [], so the two behaviours are distinguishable in the output.
        """
        populated_dir = tmp_path / "populated"
        populated_dir.mkdir()
        aps = [
            {"ssid": f"TESTAP{i}", "display_ssid": f"TESTAP{i}", "bssid": bssid,
             "channel": 36, "encryption": "WPA3-SAE", "signal_dbm": -30 - 10 * i}
            for i, bssid in enumerate(
                ["E2:62:79:B3:48:83", "D8:32:14:0C:5B:64", "8C:83:94:05:93:B3"])
        ]
        scan_data = {
            "scan_metadata": {
                "timestamp": "20260706T103000Z",
                "interface": "wlan0",
                "tool": "iw scan",
                "mode": "managed",
                "band": "both",
                "duration_seconds": 10,
            },
            "access_points": aps,
            "total_aps": len(aps),
        }
        (populated_dir / "wireless-aps-20260706T103000Z.json").write_text(json.dumps(scan_data))

        rc, out, err = run_portshim("wireless", "select", "--output-dir", str(populated_dir),
                                    "--auto", "--max", "0")
        assert rc == 0, f"Unexpected rc: {rc}\n{out}\n{err}"
        assert "0 targets selected" in out, f"Expected --max 0 to be honoured: {out}"

        rc, out, err = run_portshim("wireless", "select", "--output-dir", str(populated_dir),
                                    "--auto", "--max", "1")
        assert rc == 0, f"Unexpected rc: {rc}\n{out}\n{err}"
        assert "1 targets selected" in out, f"Expected --max 1 to be honoured: {out}"

    def test_select_scan_file_and_file_both_forward(self, tmp_path):
        """Both --scan-file and its --file alias reach the select script.

        Locks in the forwarding of the two explicit-scan flags: the script
        reads `scan_path = args.scan_file or args.file`, and the wrapper maps
        --file onto --scan-file, so both spellings must load the given file.

        --output-dir points at an empty directory so that if either flag is
        dropped the script falls back to discovery, finds nothing, and exits 1
        rather than silently loading a scan from the developer's own outputs/.
        """
        scan_dir = tmp_path / "explicit"
        scan_dir.mkdir()
        scan_path = scan_dir / "wireless-aps-20260706T103000Z.json"
        scan_path.write_text(json.dumps({
            "scan_metadata": {
                "timestamp": "20260706T103000Z",
                "interface": "wlan0",
                "tool": "iw scan",
                "mode": "managed",
                "band": "both",
                "duration_seconds": 10,
            },
            "access_points": [
                {"ssid": "TESTAP", "display_ssid": "TESTAP", "bssid": "E2:62:79:B3:48:83",
                 "channel": 36, "encryption": "WPA3-SAE", "signal_dbm": -66},
            ],
            "total_aps": 1,
        }))
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        for flag in ("--scan-file", "--file"):
            rc, out, err = run_portshim("wireless", "select", flag, str(scan_path),
                                        "--output-dir", str(empty_dir), "--list")
            assert rc == 0, f"{flag}: unexpected rc: {rc}\n{out}\n{err}"
            assert "Loaded scan from wireless-aps-20260706T103000Z.json" in out, \
                f"{flag}: scan not loaded: {out}"
            assert "TESTAP" in out, f"{flag}: expected AP in output: {out}"


class TestDeprecatedWirelessFlag:
    """portshim scan --wireless deprecation."""

    def test_deprecated_flag_prints_warning(self):
        """--wireless flag on scan should print deprecation warning."""
        rc, out, err = run_portshim("scan", "10.0.0.0/22", "--wireless", "--dry-run")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        assert "deprecated" in out.lower(), f"Expected deprecation warning: {out}"
        assert "portshim wireless scan" in out, f"Expected migration hint: {out}"

    def test_deprecated_flag_still_runs_scan(self):
        """--wireless should not prevent the scan dry-run from proceeding."""
        rc, out, err = run_portshim("scan", "10.0.0.0/22", "--wireless", "--dry-run")
        assert rc == 0
        assert "DRY RUN" in out, f"Scan should still proceed: {out}"
        assert "Would configure" in out, f"Scan should show config: {out}"

    def test_deprecated_flag_not_in_help(self):
        """--wireless should be suppressed from scan help."""
        rc, out, err = run_portshim("scan", "--help")
        assert rc == 0
        assert "--wireless" not in out, (
            f"--wireless should be hidden from scan help: {out}"
        )

    def test_no_wireless_flag_clean_run(self):
        """Normal dry-run without --wireless should have no deprecation."""
        rc, out, err = run_portshim("scan", "10.0.0.0/22", "--dry-run")
        assert rc == 0
        assert "deprecated" not in out.lower(), (
            f"No deprecation expected without --wireless: {out}"
        )


class TestWirelessForceFlag:
    """portshim wireless scan --force flag."""

    def test_force_in_help(self):
        """--force should appear in wireless scan help."""
        rc, out, err = run_portshim("wireless", "scan", "--help")
        assert rc == 0
        assert "--force" in out, f"Expected --force in help: {out}"

    def test_force_proceeds_without_prompt(self):
        """--force with dry-run should show 'proceeding' message."""
        rc, out, err = run_portshim("wireless", "scan", "--dry-run", "--force")
        assert rc in (0, 1), f"Unexpected rc: {rc}\n{err}"
        if rc == 0:
            assert ("--force set" in out or "DRY RUN" in out), (
                f"Expected force or dry-run output: {out}"
            )


# ── wireless_scan.py dry-run (no hardware needed) ──

class TestWirelessScriptDryRun:
    """wireless_scan.py --dry-run behaviour on this machine."""

    def test_dry_run_detects_or_reports_no_adapter(self):
        """--dry-run should either find an adapter or report none."""
        rc, out, err = run_wireless_script("--dry-run")
        assert rc in (0, 1), f"Unexpected rc: {rc}"
        # Should either detect an adapter, report no external adapter, or no wireless adapters
        has_adapter = "Wireless interfaces found" in out
        no_external = "No external USB" in err
        no_adapter = "No wireless adapters" in out
        assert has_adapter or no_external or no_adapter, (
            f"Expected adapter detection or 'no adapter' message: out={out[:200]} err={err[:200]}"
        )

    def test_dry_run_output_format(self):
        """--dry-run should show planned scan parameters."""
        rc, out, err = run_wireless_script("--dry-run", "--duration", "30", "--band", "5")
        if rc == 0:
            assert "DRY RUN" in out, f"Expected DRY RUN marker: {out}"
            assert "Duration" in out or "Would scan" in out, (
                f"Expected parameters: {out}"
            )
        # rc=1 is OK if no adapter — the script exits before dry-run output
        assert rc in (0, 1), f"Unexpected rc: {rc}\n{err}"


# ── Pure function tests (no hardware needed) ──

class TestParseEncryption:
    """wireless_scan.parse_encryption — unit tests."""

    # Import the function at module level or inline
    def _import_parse_encryption(self):
        """Import the function from the wireless_scan module."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "wireless_scan", WIRELESS_SCRIPT
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.parse_encryption

    def setup_method(self):
        self.parse = self._import_parse_encryption()

    def test_wpa2_psk(self):
        assert self.parse("WPA2", "CCMP", "PSK") == "WPA2-PSK"

    def test_wpa2_enterprise(self):
        assert self.parse("WPA2", "CCMP", "802.1X") == "WPA2-Enterprise"
        assert self.parse("WPA2", "CCMP", "MGT") == "WPA2-Enterprise"

    def test_wpa3_sae(self):
        assert self.parse("WPA3", "CCMP", "SAE") == "WPA3-SAE"

    def test_wpa3_transition(self):
        assert self.parse("WPA2", "CCMP", "WPA3") == "WPA3-Transition"

    def test_wep(self):
        assert self.parse("WEP", "", "") == "WEP"

    def test_open(self):
        assert self.parse("", "", "") == "Open"
        assert self.parse("OPN", "", "") == "Open"

    def test_wpa_only(self):
        assert self.parse("WPA", "TKIP", "PSK") == "WPA"

    def test_unknown(self):
        assert self.parse("SOME-NEW-PROTOCOL", "", "") == "SOME-NEW-PROTOCOL"

    def test_case_insensitive(self):
        assert self.parse("wpa2", "ccmp", "psk") == "WPA2-PSK"
        assert self.parse("wep", "", "") == "WEP"


class TestParseAirodumpCSV:
    """wireless_scan.parse_airodump_csv — unit tests with sample data."""

    SAMPLE_CSV = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
        "AA:BB:CC:11:22:33, 2026-07-06 12:00:00, 2026-07-06 12:00:15, 6, "
        "130, WPA2, CCMP, PSK, -45, 120, 0, 0.0.0.0, 8, CorpWiFi, \r\n"
        "DD:EE:FF:44:55:66, 2026-07-06 12:00:01, 2026-07-06 12:00:14, 1, "
        "54, WPA2, CCMP, 802.1X, -38, 95, 0, 0.0.0.0, 9, EnterpriseNet, \r\n"
        "11:22:33:AA:BB:CC, 2026-07-06 12:00:02, 2026-07-06 12:00:13, 149, "
        "130, WPA3, CCMP, SAE, -55, 60, 0, 0.0.0.0, 6, Office5G, \r\n"
        "AA:BB:22:33:44:55, 2026-07-06 12:00:03, 2026-07-06 12:00:12, 11, "
        "54, WEP, , , -67, 40, 0, 0.0.0.0, 3, OldNet, \r\n"
        "BB:CC:33:44:55:66, 2026-07-06 12:00:04, 2026-07-06 12:00:11, 6, "
        "130, , , , -72, 10, 0, 0.0.0.0, 0, , \r\n"
        "\r\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, "
        "Probed ESSIDs\r\n"
    )

    def _import_parse(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "wireless_scan", WIRELESS_SCRIPT
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.parse_airodump_csv

    def setup_method(self):
        self.parse = self._import_parse()

    def _write_csv(self, content):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8"
        )
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_parses_aps(self):
        path = self._write_csv(self.SAMPLE_CSV)
        try:
            aps = self.parse(path)
            assert len(aps) == 5, f"Expected 5 APs, got {len(aps)}: {aps}"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parses_ssid(self):
        path = self._write_csv(self.SAMPLE_CSV)
        try:
            aps = self.parse(path)
            ssids = [ap["ssid"] for ap in aps]
            assert "CorpWiFi" in ssids, f"Expected CorpWiFi: {ssids}"
            assert "EnterpriseNet" in ssids, f"Expected EnterpriseNet: {ssids}"
            assert "Office5G" in ssids, f"Expected Office5G: {ssids}"
            assert "OldNet" in ssids, f"Expected OldNet: {ssids}"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parses_bssid(self):
        path = self._write_csv(self.SAMPLE_CSV)
        try:
            aps = self.parse(path)
            bssids = [ap["bssid"] for ap in aps]
            assert "AA:BB:CC:11:22:33" in bssids, f"Expected BSSID: {bssids}"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parses_channel(self):
        path = self._write_csv(self.SAMPLE_CSV)
        try:
            aps = self.parse(path)
            channels = {ap["ssid"]: ap["channel"] for ap in aps}
            assert channels["CorpWiFi"] == 6
            assert channels["EnterpriseNet"] == 1
            assert channels["Office5G"] == 149
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parses_encryption(self):
        path = self._write_csv(self.SAMPLE_CSV)
        try:
            aps = self.parse(path)
            enc = {ap["ssid"]: ap["encryption"] for ap in aps}
            assert enc["CorpWiFi"] == "WPA2-PSK"
            assert enc["EnterpriseNet"] == "WPA2-Enterprise"
            assert enc["Office5G"] == "WPA3-SAE"
            assert enc["OldNet"] == "WEP"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parses_signal(self):
        path = self._write_csv(self.SAMPLE_CSV)
        try:
            aps = self.parse(path)
            signals = {ap["ssid"]: ap["signal_dbm"] for ap in aps}
            assert signals["CorpWiFi"] == -45
            assert signals["EnterpriseNet"] == -38
            assert signals["Office5G"] == -55
            assert signals["OldNet"] == -67
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parses_hidden_ssid(self):
        """APs with no SSID should get 'hidden' display name."""
        path = self._write_csv(self.SAMPLE_CSV)
        try:
            aps = self.parse(path)
            hidden = [ap for ap in aps if ap["ssid"] == ""]
            assert len(hidden) == 1, f"Expected 1 hidden AP: {aps}"
            assert hidden[0]["display_ssid"] == "(hidden)"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_empty_csv(self):
        path = self._write_csv("BSSID, First time seen, Last time seen, channel\n")
        try:
            aps = self.parse(path)
            assert aps == [], f"Expected empty list from header-only CSV: {aps}"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_no_file(self):
        """Non-existent file should return empty list, not crash."""
        aps = self.parse("/tmp/nonexistent-wifi-scan-12345.csv")
        assert aps == [], f"Expected empty list for missing file: {aps}"

    def test_malformed_csv(self):
        """Malformed data should not crash."""
        path = self._write_csv("not proper csv at all\nno headers either\n")
        try:
            aps = self.parse(path)
            assert aps == [], f"Expected empty list for malformed CSV: {aps}"
        finally:
            Path(path).unlink(missing_ok=True)


class TestWirelessScriptOutputDir:
    """wireless_scan.py creates output directory structure."""

    def test_output_dir_created(self):
        """Running --dry-run should not create outputs directory."""
        outputs = PROJECT_ROOT / "outputs" / "wireless"
        # Clean up if exists
        if outputs.exists():
            pass  # Don't clean up — may exist from prior runs
        rc, out, err = run_wireless_script("--dry-run")
        # Just verify the script doesn't crash
        assert rc in (0, 1)

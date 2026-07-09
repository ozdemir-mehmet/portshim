"""Tests for scripts/wireless_deauth.py — client deauthentication."""

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add project root so we can import the script modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Fixtures ──


@pytest.fixture
def sample_targets():
    """Sample targets list matching the assess/targets file format."""
    return [
        {"ssid": "TESTAP", "bssid": "E2:62:79:B3:48:83",
         "channel": 36, "encryption": "WPA3-SAE", "signal_dbm": -66},
        {"ssid": "TESTAP_EXT", "bssid": "D8:32:14:0C:5B:64",
         "channel": 6, "encryption": "WPA2-PSK", "signal_dbm": -30},
    ]


# ── Test: find_latest_targets() ──


class TestFindLatestTargets:
    """Tests for finding the most recent targets file."""

    def test_returns_none_when_no_dir(self, monkeypatch):
        """Returns None when the output directory doesn't exist."""
        from scripts.wireless_deauth import find_latest_targets
        monkeypatch.setattr("scripts.wireless_deauth.OUTPUT_DIR",
                            Path("/nonexistent"))
        assert find_latest_targets() is None

    def test_returns_none_when_no_files(self, tmp_path, monkeypatch):
        """Returns None when no targets-*.json files exist."""
        from scripts.wireless_deauth import find_latest_targets
        monkeypatch.setattr("scripts.wireless_deauth.OUTPUT_DIR", tmp_path)
        assert find_latest_targets() is None

    def test_finds_latest(self, tmp_path, monkeypatch):
        """Returns the most recent targets-*.json file."""
        from scripts.wireless_deauth import find_latest_targets
        monkeypatch.setattr("scripts.wireless_deauth.OUTPUT_DIR", tmp_path)
        (tmp_path / "targets-20260706T100000Z.json").write_text("{}")
        new = tmp_path / "targets-20260706T110000Z.json"
        new.write_text("{}")
        assert find_latest_targets() == new


# ── Test: detect_clients_on_ap() ──


class TestDetectClients:
    """Tests for detecting associated clients on a target AP."""

    def test_returns_empty_list_without_airodump(self, monkeypatch):
        """Returns empty list when airodump-ng isn't installed."""
        from scripts.wireless_deauth import detect_clients_on_ap
        monkeypatch.setattr("scripts.wireless_deauth.shutil.which",
                            lambda t: None)
        result = detect_clients_on_ap("wlan0mon", "AA:BB:CC:DD:EE:FF", 5)
        assert result == []

    def test_detects_clients(self, monkeypatch):
        """Parses client MACs from airodump-ng CSV."""
        from scripts.wireless_deauth import detect_clients_on_ap

        def mock_run(*args, **kwargs):
            cmd = args[0]
            if "airodump-ng" in cmd and "--bssid" not in cmd:
                return MagicMock(
                    returncode=0,
                    stdout="",
                    stderr="",
                )
            return MagicMock(returncode=0, stdout="", stderr="")

        with (
            patch("subprocess.Popen") as mock_popen,
            patch("scripts.wireless_deauth.subprocess.run", mock_run),
            patch("scripts.wireless_deauth.os.killpg"),
            patch("scripts.wireless_deauth.time.sleep"),
        ):
            proc = MagicMock()
            mock_popen.return_value = proc

            # Simulate CSV output with clients
            csv_content = (
                "BSSID, First time seen, Last time seen, channel, Speed, "
                "Privacy, Cipher, Authentication, Power, # beacons, # IV, "
                "LAN IP, ID-length, ESSID, Key\n"
                "AA:BB:CC:DD:EE:FF, 10:00:00, 10:01:00, 6, 130, "
                "WPA2, CCMP, PSK, -60, 100, 0, 0.0.0.0, 6, TestAP, \n"
                "\n"
                "Station MAC, First time seen, Last time seen, Power, "
                "# packets, BSSID, Probed ESSIDs\n"
                "11:22:33:44:55:66, 10:00:00, 10:01:00, -50, 200, "
                "AA:BB:CC:DD:EE:FF, TestAP\n"
                "AA:BB:CC:DD:EE:01, 10:00:00, 10:01:00, -55, 100, "
                "AA:BB:CC:DD:EE:FF, HomeNet\n"
            )
            # Write CSV to the expected airodump output path
            def mock_wait(timeout=None):
                csv_path = Path("/tmp/airodump-tmp-01.csv")
                csv_path.parent.mkdir(parents=True, exist_ok=True)
                csv_path.write_text(csv_content)

            proc.wait = mock_wait

            result = detect_clients_on_ap("wlan0mon", "AA:BB:CC:DD:EE:FF", 5)

        assert len(result) > 0
        assert "11:22:33:44:55:66" in result
        assert "AA:BB:CC:DD:EE:01" in result

    def test_returns_empty_when_no_clients(self, monkeypatch):
        """Returns empty list when no clients associated."""
        from scripts.wireless_deauth import detect_clients_on_ap

        with (
            patch("subprocess.Popen") as mock_popen,
            patch("scripts.wireless_deauth.os.killpg"),
            patch("scripts.wireless_deauth.time.sleep"),
        ):
            proc = MagicMock()
            mock_popen.return_value = proc

            def mock_wait(timeout=None):
                # Write CSV with AP but no stations
                csv_content = (
                    "BSSID, First time seen, Last time seen, channel, "
                    "Speed, Privacy, Cipher, Authentication, Power, "
                    "# beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
                    "AA:BB:CC:DD:EE:FF, 10:00:00, 10:01:00, 6, 130, "
                    "WPA2, CCMP, PSK, -60, 100, 0, 0.0.0.0, 6, TestAP, \n"
                    "\n"
                    "Station MAC, First time seen, Last time seen, Power, "
                    "# packets, BSSID, Probed ESSIDs\n"
                )
                csv_path = Path("/tmp/airodump-tmp-01.csv")
                csv_path.parent.mkdir(parents=True, exist_ok=True)
                csv_path.write_text(csv_content)

            proc.wait = mock_wait

            result = detect_clients_on_ap("wlan0mon", "AA:BB:CC:DD:EE:FF", 5)

        assert result == []


# ── Test: send_deauth() ──


class TestSendDeauth:
    """Tests for sending deauthentication frames."""

    def test_sends_deauth_to_bssid(self, monkeypatch):
        """Sends deauth frames targeting a BSSID."""
        from scripts.wireless_deauth import send_deauth

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = send_deauth(
                iface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                count=5,
            )

        # Verify correct aireplay-ng command
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "aireplay-ng" in args[0]
        assert "-0" in args
        assert "5" in args  # count
        assert "-a" in args
        assert "AA:BB:CC:DD:EE:FF" in args
        assert "wlan0mon" in args

        assert result["success"] is True
        assert result["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert result["count"] == 5

    def test_sends_deauth_to_specific_client(self, monkeypatch):
        """Sends deauth targeting a specific client MAC."""
        from scripts.wireless_deauth import send_deauth

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = send_deauth(
                iface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                client="11:22:33:44:55:66",
                count=3,
            )

        args = mock_run.call_args[0][0]
        assert "-c" in args
        assert "11:22:33:44:55:66" in args
        assert result["client"] == "11:22:33:44:55:66"

    def test_parses_sent_frames(self, monkeypatch):
        """Parses the number of sent frames from stderr output."""
        from scripts.wireless_deauth import send_deauth

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = (
            "12:34:56  Sending DeAuth to broadcast -- BSSID: AA:BB:CC:DD:EE:FF\n"
            "12:34:56  Sending DeAuth to broadcast -- BSSID: AA:BB:CC:DD:EE:FF\n"
            "12:34:57  Sending DeAuth to broadcast -- BSSID: AA:BB:CC:DD:EE:FF\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            result = send_deauth(
                iface="wlan0mon",
                bssid="AA:BB:CC:DD:EE:FF",
                count=3,
            )

        assert result["frames_sent"] == 3

    def test_handles_no_aireplay(self, monkeypatch):
        """Returns failure when aireplay-ng is not available."""
        from scripts.wireless_deauth import send_deauth
        monkeypatch.setattr("scripts.wireless_deauth.shutil.which",
                            lambda t: None)

        result = send_deauth(
            iface="wlan0mon", bssid="AA:BB:CC:DD:EE:FF", count=5,
        )
        assert result["success"] is False
        assert "aireplay-ng" in (result.get("error") or "")


# ── Test: deauth_targets() ──


class TestDeauthTargets:
    """Tests for the multi-target deauth orchestration."""

    def test_deauths_all_targets(self, monkeypatch):
        """Runs deauth against each target."""
        from scripts.wireless_deauth import deauth_targets

        results = []

        def fake_send_deauth(**kwargs):
            results.append(kwargs)
            return {"success": True, "bssid": kwargs["bssid"],
                    "count": kwargs["count"], "frames_sent": kwargs["count"]}

        with (
            patch("scripts.wireless_deauth.send_deauth", fake_send_deauth),
            patch("scripts.wireless_deauth.detect_clients_on_ap",
                  return_value=[]),
        ):
            targets = [
                {"bssid": "AA:BB:CC:DD:EE:01"},
                {"bssid": "AA:BB:CC:DD:EE:02"},
            ]
            result = deauth_targets("wlan0mon", targets, count=5)

        assert len(result["results"]) == 2
        assert result["total_targets"] == 2
        assert result["total_successful"] == 2

    def test_skips_targets_without_bssid(self, monkeypatch):
        """Skips targets that don't have a BSSID."""
        from scripts.wireless_deauth import deauth_targets

        calls = []

        def fake_send_deauth(**kwargs):
            calls.append(kwargs)
            return {"success": True, "bssid": kwargs["bssid"]}

        with patch("scripts.wireless_deauth.send_deauth", fake_send_deauth):
            targets = [
                {"bssid": "AA:BB:CC:DD:EE:01"},
                {"ssid": "NoBSSID"},
                {"bssid": "AA:BB:CC:DD:EE:02"},
            ]
            result = deauth_targets("wlan0mon", targets, count=3)

        assert len(calls) == 2  # skipped the one without bssid
        assert result["total_skipped"] == 1

    def test_detects_clients_when_enabled(self, monkeypatch):
        """Discovers clients before deauth when --detect-clients is set."""
        from scripts.wireless_deauth import deauth_targets

        detected_clients = {"AA:BB:CC:DD:EE:01": ["11:22:33:44:55:66"]}

        def fake_detect(iface, bssid, **kw):
            return detected_clients.get(bssid, [])

        deauth_calls = []

        def fake_send_deauth(**kwargs):
            deauth_calls.append(kwargs)
            return {"success": True}

        with (
            patch("scripts.wireless_deauth.detect_clients_on_ap",
                  side_effect=fake_detect),
            patch("scripts.wireless_deauth.send_deauth", fake_send_deauth),
            patch("scripts.wireless_deauth.enable_monitor_mode",
                  return_value=True),
            patch("scripts.wireless_deauth.restore_managed_mode",
                  return_value=True),
        ):
            targets = [
                {"bssid": "AA:BB:CC:DD:EE:01"},
            ]
            result = deauth_targets(
                "wlan0", targets, count=3, detect_clients=True,
            )

        assert result["total_clients_detected"] == 1
        assert deauth_calls[0].get("client") == "11:22:33:44:55:66"

    def test_monitor_mode_setup(self, monkeypatch):
        """Sets up monitor mode before deauth."""
        from scripts.wireless_deauth import deauth_targets

        with (
            patch("scripts.wireless_deauth.send_deauth",
                  return_value={"success": True}),
            patch("scripts.wireless_deauth.detect_clients_on_ap",
                  return_value=[]),
            patch("scripts.wireless_deauth.enable_monitor_mode",
                  return_value=True) as mock_enable,
            patch("scripts.wireless_deauth.restore_managed_mode",
                  return_value=True),
        ):
            targets = [{"bssid": "AA:BB:CC:DD:EE:01"}]
            deauth_targets("wlan0", targets, count=5)

            mock_enable.assert_called_once_with("wlan0")

    def test_restores_managed_after_deauth(self, monkeypatch):
        """Restores managed mode after deauth completes."""
        from scripts.wireless_deauth import deauth_targets

        with (
            patch("scripts.wireless_deauth.send_deauth",
                  return_value={"success": True}),
            patch("scripts.wireless_deauth.detect_clients_on_ap",
                  return_value=[]),
            patch("scripts.wireless_deauth.enable_monitor_mode",
                  return_value=True),
            patch("scripts.wireless_deauth.restore_managed_mode",
                  return_value=True) as mock_restore,
        ):
            targets = [{"bssid": "AA:BB:CC:DD:EE:01"}]
            deauth_targets("wlan0", targets, count=5)

            mock_restore.assert_called_once()


# ── Test: save_deauth_result() ──


class TestSaveDeauthResult:
    """Tests for saving deauth results to JSON."""

    def test_saves_complete_result(self, tmp_path):
        """Saves deauth result with all required fields."""
        from scripts.wireless_deauth import save_deauth_result

        result = {
            "interface": "wlan0mon",
            "total_targets": 2,
            "total_successful": 2,
            "total_skipped": 0,
            "total_clients_detected": 1,
            "duration": 15,
            "results": [
                {"bssid": "AA:BB:CC:DD:EE:01", "success": True,
                 "frames_sent": 5, "client": "11:22:33:44:55:66"},
                {"bssid": "AA:BB:CC:DD:EE:02", "success": True,
                 "frames_sent": 5, "client": None},
            ],
        }
        save_deauth_result(result, tmp_path)

        files = list(tmp_path.glob("deauth-result-*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())

        assert data["deauth_metadata"]["total_targets"] == 2
        assert data["deauth_metadata"]["total_successful"] == 2
        assert data["deauth_metadata"]["total_clients_detected"] == 1

    def test_saves_failure_result(self, tmp_path):
        """Saves result when deauth fails."""
        from scripts.wireless_deauth import save_deauth_result

        result = {
            "interface": "wlan0mon",
            "total_targets": 1,
            "total_successful": 0,
            "total_skipped": 0,
            "total_clients_detected": 0,
            "duration": 5,
            "results": [
                {"bssid": "AA:BB:CC:DD:EE:01", "success": False,
                 "error": "aireplay-ng not found"},
            ],
        }
        save_deauth_result(result, tmp_path)

        files = list(tmp_path.glob("deauth-result-*.json"))
        data = json.loads(files[0].read_text())
        assert data["deauth_metadata"]["total_successful"] == 0


# ── Test: print_deauth_report() ──


class TestPrintDeauthReport:
    """Tests for terminal output formatting."""

    def strip_ansi(self, text):
        import re
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def test_shows_success_summary(self, capsys):
        """Prints success count for each target."""
        from scripts.wireless_deauth import print_deauth_report

        result = {
            "interface": "wlan0mon",
            "total_targets": 2,
            "total_successful": 2,
            "total_skipped": 0,
            "total_clients_detected": 0,
            "duration": 10,
            "results": [
                {"bssid": "AA:BB:CC:DD:EE:01", "success": True,
                 "frames_sent": 5},
                {"bssid": "AA:BB:CC:DD:EE:02", "success": True,
                 "frames_sent": 3},
            ],
        }
        print_deauth_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "2/2" in out or "successful" in out.lower()
        assert "AA:BB:CC:DD:EE:01" in out

    def test_shows_failure(self, capsys):
        """Shows when a target failed."""
        from scripts.wireless_deauth import print_deauth_report

        result = {
            "interface": "wlan0mon",
            "total_targets": 1,
            "total_successful": 0,
            "total_skipped": 0,
            "total_clients_detected": 0,
            "duration": 5,
            "results": [
                {"bssid": "AA:BB:CC:DD:EE:01", "success": False,
                 "error": "Interface not in monitor mode"},
            ],
        }
        print_deauth_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "failed" in out.lower() or "error" in out.lower()

    def test_shows_client_detection(self, capsys):
        """Shows client detection info when clients were found."""
        from scripts.wireless_deauth import print_deauth_report

        result = {
            "interface": "wlan0mon",
            "total_targets": 1,
            "total_successful": 1,
            "total_skipped": 0,
            "total_clients_detected": 2,
            "duration": 10,
            "results": [
                {"bssid": "AA:BB:CC:DD:EE:01", "success": True,
                 "frames_sent": 5, "client": "11:22:33:44:55:66"},
            ],
        }
        print_deauth_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "client" in out.lower()


# ── CLI integration tests ──


class TestCLIIntegration:
    """Tests for CLI argument parsing and entry point."""

    def test_no_arguments_exits(self, monkeypatch):
        """Running with no arguments exits with error."""
        from scripts.wireless_deauth import main
        monkeypatch.setattr(
            "scripts.wireless_deauth.find_latest_targets",
            lambda: None,
        )
        with (
            patch.object(sys, "argv", ["wireless_deauth.py"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code in (1, 2)

    def test_dry_run_shows_plan(self, capsys, monkeypatch, tmp_path):
        """Dry run prints the deauth plan without sending frames."""
        from scripts.wireless_deauth import main

        tf = tmp_path / "targets.json"
        tf.write_text(json.dumps({
            "targets": [{"bssid": "AA:BB:CC:DD:EE:01"}],
        }))

        with (
            patch.object(sys, "argv", [
                "wireless_deauth.py", "--targets-file", str(tf),
                "--dry-run",
            ]),
        ):
            main()

        out = capsys.readouterr().out
        assert "Dry Run" in out or "dry" in out.lower()

    def test_force_flag(self, tmp_path):
        """--force flag is accepted (for agent-friendly mode)."""
        from scripts.wireless_deauth import main

        tf = tmp_path / "targets.json"
        tf.write_text(json.dumps({
            "targets": [{"bssid": "AA:BB:CC:DD:EE:01"}],
        }))

        with (
            patch.object(sys, "argv", [
                "wireless_deauth.py", "--targets-file", str(tf),
                "--force",
            ]),
            patch("scripts.wireless_deauth.deauth_targets",
                  return_value={
                      "interface": "wlan0mon", "total_targets": 0,
                      "total_successful": 0, "total_skipped": 0,
                      "total_clients_detected": 0, "duration": 0,
                      "results": [],
                  }),
        ):
            main()

    def test_specify_count(self, tmp_path, monkeypatch):
        """--count argument sets number of deauth frames (dry-run shows plan)."""
        from scripts.wireless_deauth import main

        tf = tmp_path / "targets.json"
        tf.write_text(json.dumps({
            "targets": [{"bssid": "AA:BB:CC:DD:EE:01"}],
        }))

        # Ensure no leftover targets files can leak through
        monkeypatch.setattr(
            "scripts.wireless_deauth.find_latest_targets",
            lambda: None,
        )

        with patch.object(sys, "argv", [
            "wireless_deauth.py", "--targets-file", str(tf),
            "--count", "10", "--dry-run",
        ]):
            main()  # dry-run returns normally — does NOT raise SystemExit

    def test_detect_clients_flag(self, tmp_path, monkeypatch):
        """--detect-clients flag enables client detection (dry-run shows plan)."""
        from scripts.wireless_deauth import main

        tf = tmp_path / "targets.json"
        tf.write_text(json.dumps({
            "targets": [{"bssid": "AA:BB:CC:DD:EE:01"}],
        }))

        # Ensure no leftover targets files can leak through
        monkeypatch.setattr(
            "scripts.wireless_deauth.find_latest_targets",
            lambda: None,
        )

        with patch.object(sys, "argv", [
            "wireless_deauth.py", "--targets-file", str(tf),
            "--detect-clients", "--dry-run",
        ]):
            main()  # dry-run returns normally — does NOT raise SystemExit

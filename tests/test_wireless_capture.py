"""Tests for scripts/wireless_capture.py — WPA handshake capture."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, call

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


@pytest.fixture
def sample_targets_file(tmp_path, sample_targets):
    """Create a targets JSON file and return its path."""
    data = {
        "selection_metadata": {
            "timestamp": "20260706T103000Z",
            "source_scan": "wireless-aps-test.json",
            "selection_mode": "auto",
            "total_available": 5,
            "total_selected": 2,
        },
        "targets": sample_targets,
    }
    tf = tmp_path / "targets.json"
    tf.write_text(json.dumps(data))
    return tf


# ── Test: find_latest_targets() ──


class TestFindLatestTargets:
    """Tests for finding the most recent targets file."""

    def test_returns_none_when_no_dir(self, monkeypatch):
        """Returns None when the output directory doesn't exist."""
        from scripts.wireless_capture import find_latest_targets
        monkeypatch.setattr("scripts.wireless_capture.OUTPUT_DIR",
                            Path("/nonexistent/outputs/wireless"))
        assert find_latest_targets() is None

    def test_returns_none_when_no_targets(self, tmp_path, monkeypatch):
        """Returns None when no targets-*.json files exist."""
        from scripts.wireless_capture import find_latest_targets
        monkeypatch.setattr("scripts.wireless_capture.OUTPUT_DIR", tmp_path)
        assert find_latest_targets() is None

    def test_finds_latest_targets_file(self, tmp_path, monkeypatch):
        """Returns the most recent targets-*.json file."""
        from scripts.wireless_capture import find_latest_targets
        monkeypatch.setattr("scripts.wireless_capture.OUTPUT_DIR", tmp_path)

        old = tmp_path / "targets-20260706T100000Z.json"
        new = tmp_path / "targets-20260706T110000Z.json"
        old.write_text("{}")
        new.write_text("{}")

        result = find_latest_targets()
        assert result == new

    def test_ignores_other_json_files(self, tmp_path, monkeypatch):
        """Only matches targets-*.json, not other JSON files."""
        from scripts.wireless_capture import find_latest_targets
        monkeypatch.setattr("scripts.wireless_capture.OUTPUT_DIR", tmp_path)

        (tmp_path / "assessment-20260706T100000Z.json").write_text("{}")
        (tmp_path / "targets-20260706T110000Z.json").write_text("{}")

        result = find_latest_targets()
        assert result is not None
        assert "targets-" in result.name


# ── Test: load_targets() ──


class TestLoadTargets:
    """Tests for loading and validating targets files."""

    def test_loads_valid_file(self, sample_targets_file, sample_targets):
        """Returns list of targets from a valid file."""
        from scripts.wireless_capture import load_targets
        result = load_targets(sample_targets_file)
        assert result == sample_targets

    def test_exits_on_missing_targets_key(self, tmp_path):
        """Exits when file is missing the 'targets' key."""
        from scripts.wireless_capture import load_targets
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"nope": []}))

        with pytest.raises(SystemExit) as exc:
            load_targets(bad)
        assert exc.value.code == 1

    def test_exits_on_empty_targets(self, tmp_path):
        """Exits when targets list is empty."""
        from scripts.wireless_capture import load_targets
        empty = tmp_path / "empty.json"
        empty.write_text(json.dumps({"targets": []}))

        with pytest.raises(SystemExit) as exc:
            load_targets(empty)
        assert exc.value.code == 1

    def test_exits_on_json_decode_error(self, tmp_path):
        """Exits when file contains invalid JSON."""
        from scripts.wireless_capture import load_targets
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all {{{")

        with pytest.raises(SystemExit) as exc:
            load_targets(bad)
        assert exc.value.code == 1

    def test_exits_on_oserror(self, tmp_path, monkeypatch):
        """Exits when file read fails with OSError."""
        from scripts.wireless_capture import load_targets
        nonexistent = tmp_path / "nonexistent.json"

        with pytest.raises(SystemExit) as exc:
            load_targets(nonexistent)
        assert exc.value.code == 1


# ── Test: determine_target_channels() ──


class TestDetermineChannels:
    """Tests for determining which channels to listen on."""

    def test_collects_unique_channels(self, sample_targets):
        """Returns sorted unique channels from targets."""
        from scripts.wireless_capture import determine_target_channels
        channels = determine_target_channels(sample_targets)
        assert channels == [6, 36]  # sorted

    def test_handles_none_channel(self):
        """Filters out targets with no channel info."""
        from scripts.wireless_capture import determine_target_channels
        targets = [
            {"bssid": "AA:BB:CC:DD:EE:01", "channel": 1},
            {"bssid": "AA:BB:CC:DD:EE:02", "channel": None},
        ]
        channels = determine_target_channels(targets)
        assert channels == [1]


# ── Test: detect_handshakes_in_cap() ──


class TestDetectHandshakes:
    """Tests for scanning a .cap file for WPA handshakes."""

    def test_returns_zero_without_aircrack(self, monkeypatch):
        """Returns 0 when aircrack-ng is not installed."""
        from scripts.wireless_capture import detect_handshakes_in_cap
        monkeypatch.setattr("scripts.wireless_capture.shutil.which",
                            lambda t: None)
        result = detect_handshakes_in_cap("/fake.cap")
        assert result == 0

    def test_parses_handshake_count(self, monkeypatch):
        """Parses the handshake count from aircrack-ng output."""
        from scripts.wireless_capture import detect_handshakes_in_cap

        mock_result = MagicMock()
        mock_result.stdout = (
            "Opening fake.cap\n"
            "Read 42 packets.\n"
            "    #  BSSID              ESSID                     Encryption\n"
            "    1  AA:BB:CC:DD:EE:FF  TestAP                   WPA (1 handshake)\n"
            "\n"
            "Choosing first network if no BSSID specified.\n"
        )
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            count = detect_handshakes_in_cap("/fake.cap")

        assert count == 1

    def test_parses_multiple_handshakes(self, monkeypatch):
        """Parses total when multiple APs have handshakes."""
        from scripts.wireless_capture import detect_handshakes_in_cap

        mock_result = MagicMock()
        mock_result.stdout = (
            "    1  AA:BB:CC:DD:EE:01  Net1   WPA (1 handshake)\n"
            "    2  AA:BB:CC:DD:EE:02  Net2   WPA (2 handshakes)\n"
        )
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            count = detect_handshakes_in_cap("/fake.cap")

        assert count == 3

    def test_returns_zero_on_no_handshakes(self, monkeypatch):
        """Returns 0 when no handshakes found."""
        from scripts.wireless_capture import detect_handshakes_in_cap

        mock_result = MagicMock()
        mock_result.stdout = "No valid WPA handshakes found.\n"
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            count = detect_handshakes_in_cap("/fake.cap")

        assert count == 0

    def test_returns_zero_on_nonzero_returncode(self, monkeypatch):
        """Returns 0 when aircrack-ng exits with non-zero code."""
        from scripts.wireless_capture import detect_handshakes_in_cap

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "error reading file\n"

        with patch("subprocess.run", return_value=mock_result):
            count = detect_handshakes_in_cap("/fake.cap")
        assert count == 0

    def test_returns_zero_on_timeout(self, monkeypatch):
        """Returns 0 when aircrack-ng times out."""
        from scripts.wireless_capture import detect_handshakes_in_cap

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(
            cmd=["aircrack-ng", "/fake.cap"], timeout=30,
        )):
            count = detect_handshakes_in_cap("/fake.cap")
        assert count == 0

    def test_returns_zero_on_oserror(self, monkeypatch):
        """Returns 0 when subprocess.run raises OSError."""
        from scripts.wireless_capture import detect_handshakes_in_cap

        with patch("subprocess.run", side_effect=OSError("no such file")):
            count = detect_handshakes_in_cap("/fake.cap")
        assert count == 0


# ── Test: build_capture_output_path() ──


class TestBuildOutputPath:
    """Tests for constructing output file paths."""

    def test_includes_timestamp(self, tmp_path):
        """Output path includes a timestamp component."""
        from scripts.wireless_capture import build_capture_output_path
        path = build_capture_output_path(tmp_path)
        assert str(path).startswith(str(tmp_path / "capture-"))
        # airodump-ng appends -01 suffix

    def test_creates_directory(self, tmp_path):
        """Creates the output directory if it doesn't exist."""
        from scripts.wireless_capture import build_capture_output_path
        nested = tmp_path / "a" / "b"
        path = build_capture_output_path(nested)
        assert nested.exists()
        assert str(path).startswith(str(nested / "capture-"))


# ── Test: check_interface_for_monitor() ──


class TestCheckInterface:
    """Tests for checking if an interface supports monitor mode."""

    def test_returns_scan_mode(self):
        """Calls get_scan_mode from wireless_hardware and returns it."""
        from scripts.wireless_capture import check_interface_for_monitor
        with (
            patch("scripts.wireless_capture.detect_interfaces",
                  return_value=["wlan0"]),
            patch("scripts.wireless_capture.get_interface_info",
                  return_value={
                      "name": "wlan0",
                      "capabilities": {"monitor_mode": True},
                  }),
            patch("scripts.wireless_capture.get_scan_mode",
                  return_value="full"),
        ):
            mode, info = check_interface_for_monitor("wlan0")
            assert mode == "full"
            assert info is not None

    def test_exits_on_unknown_interface(self):
        """Exits with code 1 when interface is not in detect_interfaces()."""
        from scripts.wireless_capture import check_interface_for_monitor
        with (
            patch("scripts.wireless_capture.detect_interfaces",
                  return_value=["wlan0"]),
            pytest.raises(SystemExit) as exc,
        ):
            check_interface_for_monitor("wlan99")
        assert exc.value.code == 1


# ── Test: run_capture_loop() ──


class TestRunCaptureLoop:
    """Tests for the main capture loop logic."""

    def test_launches_airodump(self):
        """Launches airodump-ng with correct arguments."""
        from scripts.wireless_capture import run_capture_loop

        with patch("subprocess.Popen") as mock_popen:
            proc = MagicMock()
            mock_popen.return_value = proc

            with patch("time.sleep", return_value=None):
                result = run_capture_loop(
                    iface="wlan0mon",
                    output_prefix="/tmp/capture",
                    duration=5,
                    channels=[1, 6, 11],
                    bssids=None,
                )

        # Verify airodump was launched with correct args
        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        assert "airodump-ng" in args[0]
        assert "wlan0mon" in args
        assert "--channel" in args
        assert "1,6,11" in args  # channel list
        assert "-w" in args
        assert "/tmp/capture" in args

    def test_with_bssid_filter(self):
        """Launches airodump with BSSID filters when specified."""
        from scripts.wireless_capture import run_capture_loop

        with patch("subprocess.Popen") as mock_popen:
            proc = MagicMock()
            mock_popen.return_value = proc

            with patch("time.sleep", return_value=None):
                run_capture_loop(
                    iface="wlan0mon",
                    output_prefix="/tmp/capture",
                    duration=5,
                    channels=None,
                    bssids=["AA:BB:CC:DD:EE:FF"],
                )

        args = mock_popen.call_args[0][0]
        assert "--bssid" in args
        assert "AA:BB:CC:DD:EE:FF" in args

    def test_without_channel_filter(self):
        """Runs without --channel when no channels specified."""
        from scripts.wireless_capture import run_capture_loop

        with patch("subprocess.Popen") as mock_popen:
            proc = MagicMock()
            mock_popen.return_value = proc

            with patch("time.sleep", return_value=None):
                run_capture_loop(
                    iface="wlan0mon",
                    output_prefix="/tmp/capture",
                    duration=5,
                    channels=None,
                    bssids=None,
                )

        args = mock_popen.call_args[0][0]
        assert "--channel" not in args

    def test_writes_pcap_format(self):
        """Ensures --output-format pcap is in the airodump args."""
        from scripts.wireless_capture import run_capture_loop

        with patch("subprocess.Popen") as mock_popen:
            proc = MagicMock()
            mock_popen.return_value = proc

            with patch("time.sleep", return_value=None):
                run_capture_loop(
                    iface="wlan0mon",
                    output_prefix="/tmp/capture",
                    duration=5,
                    channels=None,
                    bssids=None,
                )

        args = mock_popen.call_args[0][0]
        assert "--output-format" in args
        assert "pcap" in args[args.index("--output-format") + 1]

    def test_sends_sigterm_on_completion(self):
        """Sends SIGTERM to airodump process after duration."""
        from scripts.wireless_capture import run_capture_loop

        with patch("subprocess.Popen") as mock_popen:
            proc = MagicMock()
            mock_popen.return_value = proc

            with patch("time.sleep", return_value=None):
                run_capture_loop(
                    iface="wlan0mon",
                    output_prefix="/tmp/capture",
                    duration=3,
                    channels=None,
                    bssids=None,
                )

        # Should have sent SIGTERM
        assert proc.send_signal.call_count >= 1
        assert proc.wait.called

    def test_handles_keyboard_interrupt(self):
        """Catches KeyboardInterrupt and terminates airodump cleanly."""
        from scripts.wireless_capture import run_capture_loop

        with patch("subprocess.Popen") as mock_popen:
            proc = MagicMock()
            mock_popen.return_value = proc

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                result = run_capture_loop(
                    iface="wlan0mon",
                    output_prefix="/tmp/capture",
                    duration=60,
                    channels=None,
                    bssids=None,
                )

        assert proc.send_signal.called
        assert proc.wait.called
        assert result["capture_file"].endswith("-01.cap")

    def test_kills_on_wait_timeout(self):
        """Kills airodump if SIGTERM+wait times out."""
        from scripts.wireless_capture import run_capture_loop

        with patch("subprocess.Popen") as mock_popen:
            proc = MagicMock()
            # SIGTERM sends fine, but first wait() times out; second succeeds
            proc.wait.side_effect = [
                subprocess.TimeoutExpired(cmd=["airodump-ng"], timeout=10),
                None,  # second wait() after kill succeeds
            ]
            mock_popen.return_value = proc

            with patch("time.sleep", return_value=None):
                result = run_capture_loop(
                    iface="wlan0mon",
                    output_prefix="/tmp/capture",
                    duration=5,
                    channels=None,
                    bssids=None,
                )

        # Should have sent SIGTERM, then killed
        assert proc.send_signal.called
        assert proc.kill.called
        assert proc.wait.call_count >= 1


# ── Test: save_capture_result() ──


class TestSaveCaptureResult:
    """Tests for saving structured capture results."""

    def test_saves_complete_structure(self, tmp_path):
        """Saves capture metadata with all required fields."""
        from scripts.wireless_capture import save_capture_result

        result = {
            "handshake_count": 1,
            "capture_file": str(tmp_path / "capture-01.cap"),
            "duration": 60,
            "interface": "wlan0mon",
            "channels": [6, 36],
            "bssids": ["AA:BB:CC:DD:EE:FF"],
            "targets_count": 2,
        }
        save_capture_result(result, tmp_path)

        files = list(tmp_path.glob("capture-result-*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())

        assert data["capture_metadata"]["handshake_count"] == 1
        assert data["capture_metadata"]["duration"] == 60
        assert data["capture_metadata"]["interface"] == "wlan0mon"
        assert data["capture_metadata"]["channels"] == [6, 36]

    def test_saves_no_handshakes(self, tmp_path):
        """Saves result even when no handshakes captured."""
        from scripts.wireless_capture import save_capture_result

        result = {
            "handshake_count": 0,
            "capture_file": str(tmp_path / "nocap.cap"),
            "duration": 30,
            "interface": "wlan0mon",
            "channels": None,
            "bssids": None,
            "targets_count": 1,
        }
        save_capture_result(result, tmp_path)

        files = list(tmp_path.glob("capture-result-*.json"))
        data = json.loads(files[0].read_text())
        assert data["capture_metadata"]["handshake_count"] == 0


# ── Test: print_capture_report() ──


class TestPrintCaptureReport:
    """Tests for terminal output formatting."""

    def strip_ansi(self, text):
        import re
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def test_shows_handshake_count(self, capsys):
        """Displays number of handshakes captured."""
        from scripts.wireless_capture import print_capture_report
        result = {
            "handshake_count": 2,
            "capture_file": "/tmp/capture-01.cap",
            "duration": 60,
            "interface": "wlan0mon",
            "channels": [1, 6, 11],
            "bssids": ["AA:BB:CC:DD:EE:FF"],
            "targets_count": 1,
        }
        print_capture_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "handshake" in out.lower()
        assert "2" in out

    def test_shows_warning_on_zero(self, capsys):
        """Shows a warning when no handshakes were captured."""
        from scripts.wireless_capture import print_capture_report
        result = {
            "handshake_count": 0,
            "capture_file": "/tmp/capture-01.cap",
            "duration": 30,
            "interface": "wlan0mon",
            "channels": [1],
            "bssids": ["AA:BB:CC:DD:EE:FF"],
            "targets_count": 1,
        }
        print_capture_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "no handshake" in out.lower() or "0" in out

    def test_includes_file_path(self, capsys):
        """Displays the capture file path."""
        from scripts.wireless_capture import print_capture_report
        result = {
            "handshake_count": 1,
            "capture_file": "/tmp/my-capture-01.cap",
            "duration": 10,
            "interface": "wlan0mon",
            "channels": [6],
            "bssids": None,
            "targets_count": 2,
        }
        print_capture_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "my-capture" in out


# ── CLI integration tests ──


class TestCLIIntegration:
    """Tests for CLI argument parsing and entry point."""

    def test_no_arguments_exits(self):
        """Running with no arguments exits with error."""
        from scripts.wireless_capture import main
        with (
            patch.object(sys, "argv", ["wireless_capture.py"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code in (1, 2)

    def test_dry_run_shows_plan(self, capsys, monkeypatch, sample_targets_file):
        """Dry run prints the plan without actually capturing."""
        from scripts.wireless_capture import main

        monkeypatch.setattr(
            "scripts.wireless_capture.find_latest_targets",
            lambda: sample_targets_file,
        )
        monkeypatch.setattr(
            "scripts.wireless_capture.load_targets",
            lambda f: json.loads(f.read_text())["targets"],
        )

        with (
            patch.object(sys, "argv", [
                "wireless_capture.py", "--dry-run",
            ]),
        ):
            main()

        out = capsys.readouterr().out
        assert "Dry Run" in out or "dry" in out.lower()

    def test_specify_interface(self):
        """--interface argument is accepted."""
        from scripts.wireless_capture import main
        with (
            patch.object(sys, "argv", [
                "wireless_capture.py", "--interface", "wlan1",
                "--dry-run",
            ]),
            patch("scripts.wireless_capture.find_latest_targets",
                  return_value=Path("/tmp/targets.json")),
            patch("scripts.wireless_capture.load_targets",
                  return_value=[{"bssid": "AA:BB:CC:DD:EE:FF"}]),
            pytest.raises(SystemExit),
        ):
            main()

    def test_specify_duration(self):
        """--duration argument is accepted."""
        from scripts.wireless_capture import main
        with (
            patch.object(sys, "argv", [
                "wireless_capture.py", "--duration", "120",
                "--dry-run",
            ]),
            patch("scripts.wireless_capture.find_latest_targets",
                  return_value=Path("/tmp/targets.json")),
            patch("scripts.wireless_capture.load_targets",
                  return_value=[{"bssid": "AA:BB:CC:DD:EE:FF"}]),
        ):
            main()  # should not raise

    def test_specify_targets_file(self, sample_targets_file):
        """--targets-file argument overrides auto-find."""
        from scripts.wireless_capture import main
        with (
            patch.object(sys, "argv", [
                "wireless_capture.py", "--targets-file",
                str(sample_targets_file), "--dry-run",
            ]),
        ):
            main()  # should not raise

    def test_missing_targets_exits(self):
        """Exits when no targets file found and none specified."""
        from scripts.wireless_capture import main
        with (
            patch.object(sys, "argv", ["wireless_capture.py"]),
            patch("scripts.wireless_capture.find_latest_targets",
                  return_value=None),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code == 1

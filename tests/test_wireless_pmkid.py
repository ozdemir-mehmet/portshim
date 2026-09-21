"""Tests for scripts/wireless_pmkid.py — passive PMKID capture via hcxdumptool."""

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
    """Sample targets list matching the targets file format."""
    return [
        {"ssid": "TESTAP-LEGACY", "bssid": "E6:62:79:B3:48:82",
         "channel": 1, "encryption": "WPA2-PSK", "signal_dbm": -41},
        {"ssid": "NEIGHBOUR", "bssid": "CC:2D:21:87:C0:D1",
         "channel": 1, "encryption": "WPA2-PSK", "signal_dbm": -81},
        {"ssid": "DIRECT-Printer", "bssid": "86:25:19:0B:90:3E",
         "channel": 6, "encryption": "WPA2-PSK", "signal_dbm": -73},
    ]


@pytest.fixture
def sample_targets_file(tmp_path, sample_targets):
    """Create a targets JSON file and return its path."""
    data = {
        "selection_metadata": {
            "timestamp": "20260713T070000Z",
            "source_scan": "wireless-aps-test.json",
            "selection_mode": "auto",
            "total_available": 10,
            "total_selected": len(sample_targets),
        },
        "targets": sample_targets,
    }
    tf = tmp_path / "targets.json"
    tf.write_text(json.dumps(data))
    return tf


# ── Test: build_channel_args() ──


class TestBuildChannelArgs:
    """Tests for converting target channels to hcxdumptool channel arguments."""

    def test_single_channel_2ghz(self):
        """Channel 1 on 2.4 GHz produces '-c 1a'."""
        from scripts.wireless_pmkid import build_channel_args
        result = build_channel_args([1])
        assert result == "1a"

    def test_single_channel_5ghz(self):
        """Channel 36 on 5 GHz produces '-c 36b'."""
        from scripts.wireless_pmkid import build_channel_args
        result = build_channel_args([36])
        assert result == "36b"

    def test_multiple_channels_deduped(self):
        """Duplicate channels are deduplicated in output."""
        from scripts.wireless_pmkid import build_channel_args
        result = build_channel_args([1, 1, 6, 6])
        assert result == "1a,6a"

    def test_mixed_bands(self):
        """Mixed 2.4 and 5 GHz channels get correct suffixes."""
        from scripts.wireless_pmkid import build_channel_args
        result = build_channel_args([1, 36, 149])
        assert result == "1a,36b,149b"

    def test_empty_channels(self):
        """Empty channel list returns empty string."""
        from scripts.wireless_pmkid import build_channel_args
        result = build_channel_args([])
        assert result == ""

    def test_six_ghz_channel(self):
        """Channel 169 on 6 GHz produces '-c 169c'."""
        from scripts.wireless_pmkid import build_channel_args
        result = build_channel_args([169])
        assert result == "169c"


# ── Test: run_pmkid_capture() ──


class TestRunPmkidCapture:
    def test_launches_hcxdumptool_with_correct_args(self):
        """hcxdumptool is called with correct interface, channels, and output."""
        from scripts.wireless_pmkid import run_pmkid_capture

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            with patch.object(Path, "exists", return_value=True):
                result = run_pmkid_capture(
                    iface="wlan1",
                    channel_arg="1a,6a",
                    output_prefix="/tmp/pmkid-capture",
                    duration=30,
                )

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "hcxdumptool" in args
        assert "wlan1" in args
        assert "1a,6a" in " ".join(args)
        assert "-w" in args
        assert any("pmkid-capture" in str(a) for a in args)
        assert "--kill-after=5" in args
        assert any("pmkid-capture" in str(a) for a in args)

    def test_returns_output_path_on_success(self, tmp_path):
        """Returns the .pcapng file path when capture succeeds."""
        from scripts.wireless_pmkid import run_pmkid_capture

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            # Simulate file was created
            with patch.object(Path, "exists", return_value=True):
                result = run_pmkid_capture(
                    iface="wlan1",
                    channel_arg="1a,1b",
                    output_prefix=str(tmp_path / "test"),
                    duration=30,
                )

        assert result is not None
        assert ".pcapng" in str(result)


# ── Test: convert_pmkid_to_hashcat() ──


class TestConvertPmkidToHashcat:
    """Tests for hcxpcapngtool conversion to hashcat format."""

    def test_converts_pcapng_to_hc22000(self):
        """hcxpcapngtool is called with correct input and output args."""
        from scripts.wireless_pmkid import convert_pmkid_to_hashcat

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = convert_pmkid_to_hashcat(
                pcapng_path="/tmp/capture.pcapng",
                output_dir=Path("/tmp"),
            )

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "hcxpcapngtool" in args[0]
        assert "-o" in args
        assert "-E" in args

    def test_returns_none_when_conversion_fails(self):
        """Returns None when hcxpcapngtool exits non-zero."""
        from scripts.wireless_pmkid import convert_pmkid_to_hashcat

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="error")
            result = convert_pmkid_to_hashcat(
                pcapng_path="/tmp/bad.pcapng",
                output_dir=Path("/tmp"),
            )

        assert result is None

    def test_returns_none_when_tool_not_found(self):
        """Returns None when hcxpcapngtool is not installed."""
        from scripts.wireless_pmkid import convert_pmkid_to_hashcat

        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = convert_pmkid_to_hashcat(
                pcapng_path="/tmp/capture.pcapng",
                output_dir=Path("/tmp"),
            )

        assert result is None


# ── Test: check_tools_available() ──


class TestCheckToolsAvailable:
    """Tests for PMKID tool availability detection."""

    def test_returns_true_when_both_tools_found(self):
        """Returns True when both hcxdumptool and hcxpcapngtool are on PATH."""
        from scripts.wireless_pmkid import check_tools_available

        with patch("shutil.which", return_value="/usr/bin/hcxdumptool"):
            assert check_tools_available() is True

    def test_returns_false_when_hcxdumptool_missing(self):
        """Returns False when hcxdumptool is not installed."""
        from scripts.wireless_pmkid import check_tools_available

        def fake_which(cmd):
            return "/usr/bin/hcxdumptool" if cmd == "hcxpcapngtool" else None

        with patch("shutil.which", side_effect=fake_which):
            assert check_tools_available() is False

    def test_returns_false_when_hcxpcapngtool_missing(self):
        """Returns False when hcxpcapngtool is not installed."""
        from scripts.wireless_pmkid import check_tools_available

        def fake_which(cmd):
            return "/usr/bin/hcxpcapngtool" if cmd == "hcxdumptool" else None

        with patch("shutil.which", side_effect=fake_which):
            assert check_tools_available() is False


# ── Test: CLI integration ──


class TestCLIIntegration:
    """CLI argument parsing and integration tests."""

    def test_dry_run_shows_plan_without_capturing(self):
        """--dry-run shows the plan and exits cleanly without hardware access."""
        from scripts import wireless_pmkid

        with patch.object(sys, "argv", [
            "wireless_pmkid.py",
            "--interface", "wlan1",
            "--duration", "30",
            "--dry-run",
        ]), patch("scripts.wireless_pmkid.check_tools_available", return_value=True):
            result = wireless_pmkid.main()

        assert result == 0

    def test_exits_when_tools_missing(self):
        """Exits with code 1 when PMKID tools are not installed."""
        from scripts import wireless_pmkid

        with patch.object(sys, "argv", [
            "wireless_pmkid.py", "--interface", "wlan1", "--duration", "30",
        ]), patch("scripts.wireless_pmkid.check_tools_available", return_value=False), \
           patch("os.geteuid", return_value=0), \
           pytest.raises(SystemExit) as exc:
            wireless_pmkid.main()

        assert exc.value.code == 1

    def test_requires_root_when_not_dry_run(self):
        """Exits when not root and not --dry-run."""
        from scripts import wireless_pmkid

        with patch.object(sys, "argv", [
            "wireless_pmkid.py", "--interface", "wlan1", "--duration", "30",
        ]), patch("scripts.wireless_pmkid.check_tools_available", return_value=True), \
           patch("os.geteuid", return_value=1000):
            result = wireless_pmkid.main()

        assert result == 1

    def test_force_flag_accepted(self):
        """--force flag is accepted without error."""
        from scripts import wireless_pmkid

        with patch.object(sys, "argv", [
            "wireless_pmkid.py", "--interface", "wlan1",
            "--duration", "30", "--force", "--dry-run",
        ]), patch("scripts.wireless_pmkid.check_tools_available", return_value=True):
            result = wireless_pmkid.main()

        assert result == 0

    def test_defaults_to_latest_targets(self):
        """Without --targets-file, uses latest targets from output dir."""
        from scripts import wireless_pmkid

        with patch.object(sys, "argv", [
            "wireless_pmkid.py", "--dry-run",
        ]), patch("scripts.wireless_pmkid.check_tools_available", return_value=True), \
           patch("scripts.wireless_pmkid.find_latest_targets", return_value=Path("/tmp/dummy.json")), \
           patch("scripts.wireless_pmkid.load_targets", return_value=[{"ssid": "test", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 1, "signal_dbm": -40}]), \
           patch("scripts.wireless_pmkid.require_external_adapter", return_value={"name": "wlan1"}):
            result = wireless_pmkid.main()
            assert result == 0

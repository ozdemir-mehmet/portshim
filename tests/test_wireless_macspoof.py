"""Tests for MAC spoofing in wireless_hardware.py."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── Test: MAC utilities ──


class TestMacUtilities:
    """Tests for MAC address get/set/spoof functions."""

    def test_get_current_mac_parses_ip_link_output(self):
        """get_current_mac parses 'ip link show' output correctly."""
        from scripts.wireless_hardware import get_current_mac

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="2: wlan1: <BROADCAST,MULTICAST> mtu 1500\n"
                       "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n",
            )
            result = get_current_mac("wlan1")

        assert result == "aa:bb:cc:dd:ee:ff"

    def test_get_current_mac_returns_none_on_failure(self):
        """Returns None when ip link fails."""
        from scripts.wireless_hardware import get_current_mac

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "ip")):
            result = get_current_mac("wlan1")

        assert result is None

    def test_is_valid_mac_accepts_valid(self):
        """Valid MAC addresses pass validation."""
        from scripts.wireless_hardware import is_valid_mac

        assert is_valid_mac("aa:bb:cc:dd:ee:ff") is True
        assert is_valid_mac("AA:BB:CC:DD:EE:FF") is True
        assert is_valid_mac("00:11:22:33:44:55") is True

    def test_is_valid_mac_rejects_invalid(self):
        """Invalid MAC addresses fail validation."""
        from scripts.wireless_hardware import is_valid_mac

        assert is_valid_mac("") is False
        assert is_valid_mac("not-a-mac") is False
        assert is_valid_mac("aa:bb:cc:dd:ee") is False  # too short
        assert is_valid_mac("aa:bb:cc:dd:ee:ff:gg") is False  # too long
        assert is_valid_mac("01:00:5e:00:00:01") is False  # multicast
        assert is_valid_mac("ff:ff:ff:ff:ff:ff") is False  # broadcast

    def test_random_mac_generates_valid_unicast(self):
        """random_mac produces a valid unicast MAC."""
        from scripts.wireless_hardware import random_mac, is_valid_mac

        for _ in range(20):
            mac = random_mac()
            assert is_valid_mac(mac), f"Invalid MAC: {mac}"

    def test_random_mac_is_locally_administered(self):
        """random_mac sets the locally-administered bit (bit 1 of first octet)."""
        from scripts.wireless_hardware import random_mac

        for _ in range(20):
            mac = random_mac()
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0x02, f"Not locally administered: {mac}"

    def test_spoof_mac_changes_address(self):
        """spoof_mac calls macchanger/ip to set new MAC."""
        from scripts.wireless_hardware import spoof_mac

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = spoof_mac("wlan1", "de:ad:be:ef:00:01")

        assert result is True
        mock_run.assert_called()  # ip link set or macchanger

    def test_restore_mac_uses_permanent_address(self):
        """restore_mac resets to permanent hardware address."""
        from scripts.wireless_hardware import restore_mac

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = restore_mac("wlan1")

        assert result is True


# ── Test: MAC lifecycle ──


class TestMacLifecycle:
    """Tests for save/spoof/restore lifecycle."""

    def test_save_and_restore_cycle(self):
        """Save MAC, spoof it, then restore — restore uses saved value."""
        from scripts.wireless_hardware import save_mac, restore_saved_mac

        save_mac("wlan1", "aa:bb:cc:dd:ee:ff")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = restore_saved_mac("wlan1")

        assert result is True
        # Should call ip link set with the saved MAC (second of three calls)
        all_args = " ".join(
            " ".join(str(a) for a in call[0][0])
            for call in mock_run.call_args_list
        )
        assert "aa:bb:cc:dd:ee:ff" in all_args

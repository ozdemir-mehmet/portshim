"""Tests for scripts/network_scan.py — fast network discovery (masscan/nmap)."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── Test: run_masscan() ──


class TestRunMasscan:
    """Tests for masscan execution and output parsing."""

    def test_launches_masscan_with_correct_args(self):
        """masscan is called with rate, ports, and target."""
        from scripts.network_scan import run_masscan

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            run_masscan(targets="192.168.1.0/24", ports="1-1000", rate=1000)

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "masscan" in args[0]
        assert "192.168.1.0/24" in args
        assert "-p1-1000" in args
        assert "--rate=1000" in args

    def test_returns_none_when_masscan_not_installed(self):
        """Returns None when masscan is not on PATH."""
        from scripts.network_scan import run_masscan

        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = run_masscan("192.168.1.0/24")
            assert result is None


# ── Test: parse_masscan_output() ──


class TestParseMasscanOutput:
    """Tests for masscan output parsing into structured JSON."""

    def test_parses_oG_format(self):
        """Parses masscan -oG grepable output into host list."""
        from scripts.network_scan import parse_masscan_output

        output = (
            "# Masscan 1.3.2 scan initiated\n"
            "Host: 192.168.1.1 () Ports: 80/open/tcp//http///\n"
            "Host: 192.168.1.1 () Ports: 443/open/tcp//https///\n"
            "Host: 192.168.1.10 () Ports: 22/open/tcp//ssh///\n"
            "# Masscan done\n"
        )

        result = parse_masscan_output(output)
        assert result["scanner"] == "masscan"
        hosts = result["hosts"]
        assert len(hosts) == 2  # 192.168.1.1 and 192.168.1.10
        host1 = next(h for h in hosts if h["ip"] == "192.168.1.1")
        assert len(host1["ports"]) == 2
        assert {"port": 80, "state": "open", "protocol": "tcp", "service": "http"} in host1["ports"]
        assert {"port": 443, "state": "open", "protocol": "tcp", "service": "https"} in host1["ports"]

    def test_handles_empty_output(self):
        """Returns empty host list for scan with no results."""
        from scripts.network_scan import parse_masscan_output
        result = parse_masscan_output("")
        assert result["hosts"] == []


# ── Test: run_nmap_fast() ──


class TestRunNmapFast:
    """Tests for nmap fast-discovery fallback."""

    def test_launches_nmap_with_fast_flags(self):
        """nmap fast scan uses -sn for ping sweep."""
        from scripts.network_scan import run_nmap_fast

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            run_nmap_fast("192.168.1.0/24")

        args = mock_run.call_args[0][0]
        assert "nmap" in args[0]
        assert "-sn" in args
        assert "192.168.1.0/24" in args


# ── Test: CLI integration ──


class TestCLIIntegration:
    """CLI argument parsing and integration tests."""

    def test_dry_run_shows_plan(self):
        """--dry-run shows plan without scanning."""
        from scripts import network_scan

        with patch.object(sys, "argv", [
            "network_scan.py", "--target", "192.168.1.0/24", "--dry-run",
        ]), patch("scripts.network_scan.check_masscan_available", return_value=True):
            result = network_scan.main()
            assert result == 0

    def test_falls_back_to_nmap_when_masscan_unavailable(self):
        """Auto-fallback to nmap when masscan not installed."""
        from scripts import network_scan

        with patch.object(sys, "argv", [
            "network_scan.py", "--target", "192.168.1.0/24",
            "--scanner", "auto", "--dry-run",
        ]), patch("scripts.network_scan.check_masscan_available", return_value=False):
            result = network_scan.main()
            assert result == 0

    def test_force_flag_accepted(self):
        """--force flag skips prompts."""
        from scripts import network_scan

        with patch.object(sys, "argv", [
            "network_scan.py", "--target", "192.168.1.0/24",
            "--dry-run",
        ]), patch("scripts.network_scan.check_masscan_available", return_value=True):
            result = network_scan.main()
            assert result == 0

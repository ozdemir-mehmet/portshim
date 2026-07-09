"""Tests for scripts/wireless_crack.py — offline WPA handshake cracking."""

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
def sample_cap(tmp_path):
    """Create a minimal .cap file for testing."""
    f = tmp_path / "handshake.cap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x00\x00")  # pcap header
    return f


@pytest.fixture
def sample_wordlist(tmp_path):
    """Create a small wordlist for testing."""
    wl = tmp_path / "words.txt"
    wl.write_text("password\n12345678\nqwerty\nwifi_key\nletmein\n")
    return wl


# ── Test: find_system_wordlist() ──


class TestFindSystemWordlist:
    """Tests for system wordlist auto-detection."""

    def test_returns_none_when_no_wordlists(self, monkeypatch):
        """Returns None when no common wordlist paths exist."""
        monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
        from scripts.wireless_crack import find_system_wordlist
        assert find_system_wordlist() is None

    def test_finds_rockyou(self, tmp_path, monkeypatch):
        """Returns path when rockyou.txt exists."""
        rockyou = tmp_path / "rockyou.txt"
        rockyou.write_text("test\n")
        monkeypatch.setattr(
            "scripts.wireless_crack.find_system_wordlist",
            lambda: str(rockyou),
        )
        from scripts.wireless_crack import find_system_wordlist
        assert find_system_wordlist() == str(rockyou)

    def test_finds_compressed_wordlist(self, tmp_path, monkeypatch):
        """Returns path for .gz wordlist as fallback."""
        gz = tmp_path / "rockyou.txt.gz"
        gz.write_text("compressed\n")
        monkeypatch.setattr(
            "scripts.wireless_crack.find_system_wordlist",
            lambda: str(gz),
        )
        from scripts.wireless_crack import find_system_wordlist
        assert find_system_wordlist() == str(gz)


# ── Test: check_wordlist() ──


class TestCheckWordlist:
    """Tests for wordlist validation."""

    def test_returns_true_for_existing_file(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        from scripts.wireless_crack import check_wordlist
        assert check_wordlist(str(wl)) is True

    def test_returns_false_for_missing_file(self):
        from scripts.wireless_crack import check_wordlist
        assert check_wordlist("/nonexistent/words.txt") is False

    def test_returns_false_for_empty_file(self, tmp_path):
        wl = tmp_path / "empty.txt"
        wl.write_text("")
        from scripts.wireless_crack import check_wordlist
        assert check_wordlist(str(wl)) is False


# ── Test: detect_backend() ──


class TestDetectBackend:
    """Tests for cracking backend auto-detection and selection."""

    def test_aircrack_explicit(self, monkeypatch):
        """Explicit aircrack returns aircrack backend."""
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", lambda t: t == "aircrack-ng" or "/usr/bin/" + t)
        from scripts.wireless_crack import detect_backend
        name, cmd = detect_backend("aircrack")
        assert name == "aircrack"
        assert "aircrack-ng" in cmd[0]

    def test_hashcat_explicit(self, monkeypatch):
        """Explicit hashcat returns hashcat backend."""
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", lambda t: t == "hashcat" or "/usr/bin/" + t)
        from scripts.wireless_crack import detect_backend
        name, cmd = detect_backend("hashcat")
        assert name == "hashcat"

    def test_auto_prefers_aircrack(self, monkeypatch):
        """Auto-detect prefers aircrack-ng when both tools available."""
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", lambda t: t == "aircrack-ng" or "/usr/bin/" + t)
        from scripts.wireless_crack import detect_backend
        name, _ = detect_backend(None)
        assert name == "aircrack"

    def test_auto_falls_back_to_hashcat(self, monkeypatch):
        """Auto-detect falls back to hashcat when aircrack missing."""
        def which_side_effect(t):
            return "/usr/bin/hashcat" if t == "hashcat" else None
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", which_side_effect)
        from scripts.wireless_crack import detect_backend
        name, _ = detect_backend(None)
        assert name == "hashcat"

    def test_auto_exits_when_no_tool(self, monkeypatch):
        """Auto-detect exits when no cracking tool found."""
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", lambda t: None)
        from scripts.wireless_crack import detect_backend
        with pytest.raises(SystemExit):
            detect_backend(None)

    def test_unknown_backend_exits(self, monkeypatch):
        """Unknown backend name exits."""
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", lambda t: False)
        from scripts.wireless_crack import detect_backend
        with pytest.raises(SystemExit):
            detect_backend("nonexistent_tool")


# ── Test: run_aircrack() ──


class TestRunAircrack:
    """Tests for aircrack-ng execution and output parsing."""

    def test_parses_psk_from_stdout(self):
        """Parses PSK when aircrack writes key to stdout via -l /dev/stdout."""
        from scripts.wireless_crack import run_aircrack

        mock_result = MagicMock()
        mock_result.stdout = "my_wifi_key_123\n"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = run_aircrack("/fake.cap", "/fake.txt", 30)

        assert result["success"] is True
        assert result["psk"] == "my_wifi_key_123"

    def test_parses_psk_from_bracket_pattern(self):
        """Parses PSK from 'KEY FOUND! [ key ]' pattern in stderr."""
        from scripts.wireless_crack import run_aircrack

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = (
            "BSSID = AA:BB:CC:DD:EE:FF\n"
            "Station = 11:22:33:44:55:66\n"
            "KEY FOUND! [ supersecret ]\n"
        )
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = run_aircrack("/fake.cap", "/fake.txt", 30)

        assert result["success"] is True
        assert result["psk"] == "supersecret"
        assert result["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert result["station"] == "11:22:33:44:55:66"

    def test_no_key_found(self):
        """Returns success=False when aircrack finds nothing."""
        from scripts.wireless_crack import run_aircrack

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = "No valid handshake found in capture."
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = run_aircrack("/fake.cap", "/fake.txt", 30)

        assert result["success"] is False
        assert result["psk"] is None

    def test_includes_metadata(self):
        """Result includes time_taken, command, and exit_code."""
        from scripts.wireless_crack import run_aircrack

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = "KEY FOUND! [ testkey ]\n"
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = run_aircrack("/fake.cap", "/fake.txt", 30)

        assert "time_taken" in result
        assert "command" in result
        assert result["exit_code"] == 0


# ── Test: run_hashcat() ──


class TestRunHashcat:
    """Tests for hashcat backend execution."""

    def test_no_hcxpcapngtool(self, monkeypatch):
        """Returns error when hcxpcapngtool is not installed."""
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", lambda t: None)
        from scripts.wireless_crack import run_hashcat

        result = run_hashcat("/fake.cap", "/fake.txt", 30)
        assert result["success"] is False
        assert result["error"] is not None

    def test_no_handshake_in_capture(self, monkeypatch):
        """Returns error when capture doesn't contain a handshake."""
        monkeypatch.setattr("scripts.wireless_crack.shutil.which", lambda t: "/usr/bin/hcxpcapngtool")

        # Mock subprocess.run for hcxpcapngtool to succeed but not create output
        from scripts.wireless_crack import run_hashcat
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            result = run_hashcat("/fake.cap", "/fake.txt", 30)

        assert result["success"] is False
        assert "No handshake" in (result.get("error") or "")


# ── Test: crack() ──


class TestCrack:
    """Tests for the crack dispatch function."""

    def test_missing_cap_file_returns_error(self):
        """Returns error dict for non-existent capture file."""
        from scripts.wireless_crack import crack
        result = crack("/nonexistent.cap", "/fake.txt", "aircrack", 30)
        assert result["success"] is False
        assert "not found" in (result.get("error") or "").lower()

    def test_unknown_backend_returns_error(self):
        """Returns error dict for unknown backend."""
        from scripts.wireless_crack import crack
        # Create a fake cap file so it passes the existence check
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".cap") as f:
            result = crack(f.name, "/fake.txt", "unknown_backend", 30)
        assert result["success"] is False


# ── Test: print_result_report() ──


class TestPrintResultReport:
    """Tests for terminal output formatting."""

    def strip_ansi(self, text):
        import re
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def test_shows_key_found(self, capsys):
        """Prints KEY FOUND when PSK is recovered."""
        from scripts.wireless_crack import print_result_report
        result = {
            "success": True,
            "psk": "my_secret_key",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "time_taken": 42.5,
            "command": "aircrack-ng -w wordlist.txt cap.cap",
        }
        print_result_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "KEY FOUND" in out
        assert "my_secret_key" in out

    def test_shows_not_found(self, capsys):
        """Prints 'Key not found' when unsuccessful."""
        from scripts.wireless_crack import print_result_report
        result = {"success": False, "time_taken": 60.0}
        print_result_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "Key not found" in out

    def test_shows_error(self, capsys):
        """Prints error message when present."""
        from scripts.wireless_crack import print_result_report
        result = {"error": "Something went wrong"}
        print_result_report(result)
        out = self.strip_ansi(capsys.readouterr().out)
        assert "Something went wrong" in out


# ── Test: save_result() ──


class TestSaveResult:
    """Tests for saving crack results to JSON."""

    def test_saves_success_result(self, tmp_path):
        """Saves successful crack result with correct structure."""
        from scripts.wireless_crack import save_result
        result = {
            "success": True,
            "psk": "test_key",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "time_taken": 5.0,
        }
        save_result(result, "/fake.cap", "/fake.txt", "aircrack", tmp_path)
        files = list(tmp_path.glob("crack-result-*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["result"]["success"] is True
        assert data["result"]["psk"] == "test_key"
        assert data["crack_metadata"]["backend"] == "aircrack"

    def test_saves_failure_result(self, tmp_path):
        """Saves failure result without PSK."""
        from scripts.wireless_crack import save_result
        result = {"success": False, "error": "No handshake found"}
        save_result(result, "/nocap.cap", "/nowords.txt", "hashcat", tmp_path)
        files = list(tmp_path.glob("crack-result-*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["result"]["success"] is False
        assert data["result"]["psk"] is None

    def test_includes_capture_filename(self, tmp_path):
        """Metadata includes the source capture filename."""
        from scripts.wireless_crack import save_result
        save_result({}, "/captures/wpa_handshake.cap", "/words.txt", "aircrack", tmp_path)
        files = list(tmp_path.glob("crack-result-*.json"))
        data = json.loads(files[0].read_text())
        assert data["crack_metadata"]["source_capture"] == "wpa_handshake.cap"


# ── CLI integration tests ──


class TestCLIIntegration:
    """Tests for CLI argument parsing and script entry point."""

    def test_no_arguments_exits_with_error(self):
        """Running with no arguments should exit with error."""
        from scripts.wireless_crack import main
        with (
            patch.object(sys, "argv", ["wireless_crack.py"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        # argparse exits with code 2 when required args are missing
        assert exc.value.code == 2

    def test_missing_cap_file_exits(self):
        """Running with non-existent --cap exits."""
        from scripts.wireless_crack import main
        with (
            patch.object(sys, "argv", ["wireless_crack.py", "--cap", "/nonexistent.cap"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code == 1

    def test_dry_run_prints_plan(self, capsys, monkeypatch):
        """Dry run should print plan without cracking."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".cap") as cap:
            with tempfile.NamedTemporaryFile(suffix=".txt", mode="w") as wl:
                wl.write("password\n")
                wl.flush()

                from scripts.wireless_crack import main
                with (
                    patch.object(sys, "argv", [
                        "wireless_crack.py", "--cap", cap.name,
                        "--wordlist", wl.name, "--dry-run",
                    ]),
                ):
                    main()
                out = capsys.readouterr().out
                assert "Dry Run" in out

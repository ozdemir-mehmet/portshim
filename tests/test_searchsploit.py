"""Tests for searchsploit integration in generate-findings.py."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load the hyphenated module
_spec = importlib.util.spec_from_file_location(
    "generate_findings",
    PROJECT_ROOT / "scripts" / "generate-findings.py",
)
_gf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gf)

lookup_exploit = _gf.lookup_exploit


class TestSearchsploit:
    """Tests for searchsploit CVE lookup."""

    def setup_method(self):
        """Clear the lookup_exploit cache between tests."""
        if hasattr(lookup_exploit, "_cache"):
            lookup_exploit._cache.clear()

    def test_lookup_returns_exploit_paths(self):
        """searchsploit finds exploits for a CVE."""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=(
                    "-----------------------------------------------------------"
                    "----------------------------------------\n"
                    " Exploit Title                           |  Path\n"
                    "-----------------------------------------------------------"
                    "----------------------------------------\n"
                    "Apache 2.4.x - Buffer Overflow           | /usr/share/exploitdb/exploits/linux/remote/12345.c\n"
                    "Apache 2.4.49 - Path Traversal           | /usr/share/exploitdb/exploits/multiple/webapps/50383.py\n"
                    "-----------------------------------------------------------"
                    "----------------------------------------\n"
                    "Shellcodes: No Results\n"
                ),
            )
            result = lookup_exploit("CVE-2021-41773")

        assert len(result) == 2
        assert result[0]["title"] == "Apache 2.4.x - Buffer Overflow"
        assert "12345.c" in result[0]["path"]

    def test_lookup_no_results(self):
        """Returns empty list when no exploits found."""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Exploits: No Results\nShellcodes: No Results\n",
            )
            result = lookup_exploit("CVE-9999-0000")

        assert result == []

    def test_lookup_tool_missing(self):
        """Returns empty list when searchsploit not installed."""

        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = lookup_exploit("CVE-2021-41773")
            assert result == []

    def test_lookup_tool_timeout(self):
        """Returns empty list on timeout."""

        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("searchsploit", 10)):
            result = lookup_exploit("CVE-2021-41773")
            assert result == []

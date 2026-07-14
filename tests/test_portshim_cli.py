"""Tests for the portshim CLI server management commands."""

import subprocess, sys, tempfile, time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PORTSHIM_BIN = sys.executable  # Use same python
PORTSHIM_SCRIPT = str(PROJECT_ROOT / "portshim")


def run_portshim(*args):
    """Run portshim CLI and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [PORTSHIM_BIN, PORTSHIM_SCRIPT] + list(args),
        capture_output=True, text=True, timeout=30,
        cwd=PROJECT_ROOT,
    )
    # Normalise output by replacing colours
    clean = result.stdout.replace("\033[92m", "").replace("\033[91m", "")
    clean = clean.replace("\033[96m", "").replace("\033[93m", "")
    clean = clean.replace("\033[1m", "").replace("\033[0m", "")
    return result.returncode, clean, result.stderr


class TestServerStatus:
    """portshim server status when no server is running."""

    def test_status_stopped(self):
        rc, out, err = run_portshim("server", "status")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        assert "Stopped" in out or "stopped" in out, f"Expected Stopped in: {out}"


class TestServerModels:
    """portshim server models — lists GGUF files."""

    def test_models_lists_available(self):
        rc, out, err = run_portshim("server", "models")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        # Should show at least qwen3-coder
        assert "qwen3-coder" in out, f"Expected model listing in: {out}"
        assert "GiB" in out, f"Expected file sizes in: {out}"


class TestDryRun:
    """portshim scan --dry-run should mention server management."""

    def test_dry_run_shows_server_info(self):
        rc, out, err = run_portshim("scan", "10.0.0.0/22", "--dry-run")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        assert "Would start llama-server" in out, f"Expected server mention: {out}"
        assert "Ready to Start" in out or "Ready" in out, f"Expected ready message: {out}"

    def test_dry_run_cloud_no_server(self):
        rc, out, err = run_portshim("scan", "10.0.0.0/22", "--dry-run", "--mode", "cloud")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        assert "Would start llama-server" not in out, f"Cloud mode shouldn't start server: {out}"

    def test_dry_run_no_server_flag(self):
        rc, out, err = run_portshim("scan", "10.0.0.0/22", "--dry-run", "--no-server")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        assert "Would start llama-server" not in out, f"--no-server should skip: {out}"


class TestHelp:
    """Help output should mention server commands."""

    def test_help_shows_server(self):
        rc, out, err = run_portshim("--help")
        assert rc == 0
        assert "server" in out, f"Expected server in help: {out}"
        assert "scan" in out, f"Expected scan in help: {out}"

    def test_server_help_shows_subcommands(self):
        rc, out, err = run_portshim("server", "--help")
        assert rc == 0, f"Unexpected rc: {rc}\n{err}"
        for cmd in ["start", "stop", "status", "models", "restart"]:
            assert cmd in out, f"Expected '{cmd}' in server help: {out}"

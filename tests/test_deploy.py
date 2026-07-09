#!/usr/bin/env python3
"""Tests for deploy.py — distro-aware bootstrap, PATH setup, shell config."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the module directly
DEPLOY_PY = Path(__file__).resolve().parent.parent / "deploy.py"

# We'll exec the module for access to ensure_go_bin_in_path
import importlib.util
spec = importlib.util.spec_from_file_location("deploy", DEPLOY_PY)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

ensure_go_bin_in_path = deploy.ensure_go_bin_in_path


# ---------------------------------------------------------------------------
# ensure_go_bin_in_path — shell-agnostic PATH setup
# ---------------------------------------------------------------------------

class TestEnsureGoBinInPath:
    """Tests that ensure_go_bin_in_path gracefully adapts to any shell."""

    def test_already_in_path(self, tmp_path, monkeypatch):
        """When ~/go/bin is already in PATH, does nothing."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("PATH", f"{go_bin}:{os.environ.get('PATH', '')}")
        monkeypatch.delenv("SHELL", raising=False)

        # Should not raise and not create any files
        ensure_go_bin_in_path(dry_run=False)
        # Verify no side effects
        assert not (tmp_path / ".bashrc").exists()
        assert not (tmp_path / ".zshrc").exists()

    def test_fish_config_written(self, tmp_path, monkeypatch):
        """Fish shell → writes to ~/.config/fish/config.fish with set -gx syntax."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/fish")
        monkeypatch.setenv("PATH", "/usr/bin")

        fish_dir = tmp_path / ".config" / "fish"
        fish_dir.mkdir(parents=True)
        fish_config = fish_dir / "config.fish"
        fish_config.write_text("# fish config\n")

        # Patch Path.home() to tmp_path so deploy.py looks there
        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        content = fish_config.read_text()
        assert "set -gx PATH" in content
        assert str(go_bin) in content

    def test_zsh_config_written(self, tmp_path, monkeypatch):
        """Zsh → writes to ~/.zshrc with export syntax."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setenv("PATH", "/usr/bin")

        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("# zsh config\n")

        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        content = zshrc.read_text()
        assert 'export PATH="$PATH:' in content
        assert str(go_bin) in content

    def test_bash_config_written(self, tmp_path, monkeypatch):
        """Bash → writes to ~/.bashrc with export syntax."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/bash")
        monkeypatch.setenv("PATH", "/usr/bin")

        bashrc = tmp_path / ".bashrc"
        bashrc.write_text("# bash config\n")

        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        content = bashrc.read_text()
        assert 'export PATH="$PATH:' in content
        assert str(go_bin) in content

    def test_falls_back_to_profile(self, tmp_path, monkeypatch):
        """Unknown shell → falls back to ~/.profile (POSIX)."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/dash")
        monkeypatch.setenv("PATH", "/usr/bin")

        profile = tmp_path / ".profile"
        profile.write_text("# POSIX profile\n")

        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        content = profile.read_text()
        assert 'export PATH="$PATH:' in content
        assert str(go_bin) in content

    def test_dry_run_does_not_write(self, tmp_path, monkeypatch):
        """Dry-run mode prints but does not modify files."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/bash")
        monkeypatch.setenv("PATH", "/usr/bin")

        bashrc = tmp_path / ".bashrc"
        bashrc.write_text("# bash config\n")

        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=True)

        content = bashrc.read_text()
        # Should be unchanged
        assert content == "# bash config\n"

    def test_already_configured_skips(self, tmp_path, monkeypatch):
        """If ~/go/bin is already in the config file, does not add again."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setenv("PATH", "/usr/bin")

        zshrc = tmp_path / ".zshrc"
        zshrc.write_text(f'export PATH="$PATH:{go_bin}"\n')

        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        content = zshrc.read_text()
        # Only one occurrence — no duplicate
        assert content.count(str(go_bin)) == 1

    def test_no_config_file_prints_instructions(self, tmp_path, monkeypatch, capsys):
        """No shell config found → prints instructions instead of crashing."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/ksh")
        monkeypatch.setenv("PATH", "/usr/bin")

        # Ensure no .bashrc, .zshrc, .profile, or config.fish exist
        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert str(go_bin) in captured.out
        assert "export PATH" in captured.out

    def test_fish_no_config_file_fish_syntax(self, tmp_path, monkeypatch, capsys):
        """Fish shell with no config → prints fish-format instructions."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/fish")
        monkeypatch.setenv("PATH", "/usr/bin")

        # No fish config
        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        captured = capsys.readouterr()
        assert "set -gx PATH" in captured.out
        assert str(go_bin) in captured.out

    def test_prefers_shell_config_over_others(self, tmp_path, monkeypatch):
        """Zsh user with both .bashrc and .zshrc gets .zshrc written."""
        go_bin = tmp_path / "go" / "bin"
        go_bin.mkdir(parents=True)
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setenv("PATH", "/usr/bin")

        # Both exist — active shell's config should be preferred
        bashrc = tmp_path / ".bashrc"
        bashrc.write_text("# bash config\n")
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("# zsh config\n")

        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        assert str(go_bin) in zshrc.read_text()
        assert str(go_bin) not in bashrc.read_text()

    def test_go_bin_does_not_exist_noop(self, tmp_path, monkeypatch, capsys):
        """If ~/go/bin doesn't exist, function is a no-op."""
        monkeypatch.setenv("PATH", "/usr/bin")
        monkeypatch.setenv("SHELL", "/bin/bash")

        # No go/bin created
        with patch.object(Path, "home", return_value=tmp_path):
            ensure_go_bin_in_path(dry_run=False)

        captured = capsys.readouterr()
        # No output — nothing happened
        assert captured.out == ""

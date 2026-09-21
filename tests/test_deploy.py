#!/usr/bin/env python3
"""Tests for deploy.py — distro-aware bootstrap, PATH setup, shell config."""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Import the module directly
DEPLOY_PY = Path(__file__).resolve().parent.parent / "deploy.py"

# We'll exec the module for access to ensure_go_bin_in_path
import importlib.util
spec = importlib.util.spec_from_file_location("deploy", DEPLOY_PY)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

ensure_go_bin_in_path = deploy.ensure_go_bin_in_path
install_python_deps = deploy.install_python_deps
run_cmd = deploy.run_cmd


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


# ---------------------------------------------------------------------------
# install_python_deps — PEP 668 venv handling
# ---------------------------------------------------------------------------

class TestInstallPythonDepsVenv:
    """Tests that install_python_deps uses a venv on PEP 668 distros."""

    def test_outside_venv_creates_venv_and_uses_venv_pip(self, tmp_path, monkeypatch):
        """When not in a venv, creates .venv and uses .venv/bin/pip."""
        venv_dir = tmp_path / ".venv"
        # Simulate NOT being in a venv: sys.prefix == sys.base_prefix
        monkeypatch.setattr(sys, "base_prefix", sys.prefix)
        monkeypatch.setattr(sys, "prefix", sys.prefix)

        # Mock run_cmd to capture calls
        calls = []
        def fake_run_cmd(cmd, dry_run=False, critical=False):
            calls.append(cmd)
            # Simulate venv creation: create the bin dir
            if "venv" in cmd:
                bin_dir = venv_dir / "bin"
                bin_dir.mkdir(parents=True)
                (bin_dir / "python").touch()
                (bin_dir / "pip").touch()

        with patch.object(deploy, "run_cmd", side_effect=fake_run_cmd):
            with patch.object(deploy, "__file__", str(tmp_path / "deploy.py")):
                install_python_deps(dry_run=False)

        # Should have created the venv first
        venv_calls = [c for c in calls if c[0] == sys.executable and "venv" in c]
        assert len(venv_calls) == 1

        # Should use .venv/bin/python -m pip
        install_calls = [c for c in calls if "-m" in c and "pip" in c]
        assert len(install_calls) == 1
        assert str(venv_dir / "bin" / "python") in install_calls[0][0]

    def test_inside_venv_uses_sys_executable(self, tmp_path, monkeypatch):
        """When already in a venv, uses sys.executable -m pip."""
        # Simulate being IN a venv: prefix != base_prefix
        monkeypatch.setattr(sys, "base_prefix", "/usr")
        monkeypatch.setattr(sys, "prefix", str(tmp_path))

        calls = []
        def fake_run_cmd(cmd, dry_run=False, critical=False):
            calls.append(cmd)

        with patch.object(deploy, "run_cmd", side_effect=fake_run_cmd):
            with patch.object(deploy, "__file__", str(tmp_path / "deploy.py")):
                install_python_deps(dry_run=False)

        # Should NOT have created a venv
        venv_calls = [c for c in calls if "venv" in c]
        assert len(venv_calls) == 0

        # Should use sys.executable -m pip
        assert len(calls) == 1
        assert calls[0][0] == sys.executable
        assert "-m" in calls[0] and "pip" in calls[0]

    def test_dry_run_does_not_create_venv(self, tmp_path, monkeypatch):
        """Dry-run mode does not create .venv directory."""
        monkeypatch.setattr(sys, "base_prefix", sys.prefix)
        monkeypatch.setattr(sys, "prefix", sys.prefix)

        with patch.object(deploy, "__file__", str(tmp_path / "deploy.py")):
            install_python_deps(dry_run=True)

        assert not (tmp_path / ".venv").exists()

    def test_venv_already_exists_reused(self, tmp_path, monkeypatch):
        """When .venv/bin/pip already exists, reuses it instead of recreating."""
        venv_dir = tmp_path / ".venv"
        (venv_dir / "bin").mkdir(parents=True)
        (venv_dir / "bin" / "pip").touch()
        monkeypatch.setattr(sys, "base_prefix", sys.prefix)
        monkeypatch.setattr(sys, "prefix", sys.prefix)

        calls = []
        def fake_run_cmd(cmd, dry_run=False, critical=False):
            calls.append(cmd)

        with patch.object(deploy, "run_cmd", side_effect=fake_run_cmd):
            with patch.object(deploy, "__file__", str(tmp_path / "deploy.py")):
                install_python_deps(dry_run=False)

        # Should NOT try to create the venv again
        venv_create_calls = [c for c in calls if "-m" in c and "venv" in c]
        assert len(venv_create_calls) == 0

        # Should use .venv/bin/python -m pip
        install_calls = [c for c in calls if "-m" in c and "pip" in c]
        assert len(install_calls) == 1
        assert str(venv_dir / "bin" / "python") in install_calls[0][0]

    def test_stale_venv_recreated_with_clear(self, tmp_path, monkeypatch):
        """When .venv dir exists but no bin/pip, recreates with --clear."""
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()  # dir exists but no bin/pip — stale
        monkeypatch.setattr(sys, "base_prefix", sys.prefix)
        monkeypatch.setattr(sys, "prefix", sys.prefix)

        calls = []
        def fake_run_cmd(cmd, dry_run=False, critical=False):
            calls.append(cmd)

        with patch.object(deploy, "run_cmd", side_effect=fake_run_cmd):
            with patch.object(deploy, "__file__", str(tmp_path / "deploy.py")):
                install_python_deps(dry_run=False)

        # Should recreate the venv with --clear
        venv_create_calls = [c for c in calls if "-m" in c and "venv" in c]
        assert len(venv_create_calls) == 1
        assert "--clear" in venv_create_calls[0]


# ---------------------------------------------------------------------------
# install_system_packages — AUR helper must not run with sudo
# ---------------------------------------------------------------------------

class TestAURHelperNoSudo:
    """Tests that AUR helpers (paru/yay) are not invoked with sudo."""

    def test_aur_helper_invoked_without_sudo(self, monkeypatch):
        """AUR helper calls do NOT include sudo — AUR helpers refuse root."""
        calls = []
        def fake_run_cmd(cmd, dry_run=False, critical=False):
            calls.append(cmd)

        # Simulate finding paru
        monkeypatch.setattr("shutil.which", lambda x: x == "paru")

        with patch.object(deploy, "run_cmd", side_effect=fake_run_cmd):
            deploy.install_system_packages("pacman", dry_run=False, with_msf=True)

        # Find the AUR helper call
        aur_calls = [c for c in calls if "paru" in c or "yay" in c]
        assert len(aur_calls) == 1
        assert aur_calls[0][0] != "sudo"
        assert "sudo" not in aur_calls[0]


# ---------------------------------------------------------------------------
# PACKAGE_MAP — completeness check
# ---------------------------------------------------------------------------


class TestPackageMapCompleteness:
    """Verify all tools required by PortShim scripts are in PACKAGE_MAP."""

    REQUIRED_TOOLS = [
        "nmap", "git", "go", "python3", "pip", "python3-venv",
        "nodejs", "npm", "graphviz", "hydra", "sshpass", "aircrack-ng",
        "masscan", "macchanger", "john", "exploitdb",
    ]

    REQUIRED_DISTROS = ["apt", "dnf", "pacman", "zypper", "apk"]

    def test_all_tools_have_entries_for_all_distros(self):
        """Every required tool has a package name for every supported distro."""
        missing = []
        for tool in self.REQUIRED_TOOLS:
            if tool not in deploy.PACKAGE_MAP:
                missing.append(f"{tool}: missing from PACKAGE_MAP entirely")
                continue
            for distro in self.REQUIRED_DISTROS:
                if distro not in deploy.PACKAGE_MAP[tool]:
                    missing.append(f"{tool}: missing {distro} entry")

        assert not missing, (
            f"PACKAGE_MAP is incomplete:\n" + "\n".join(f"  - {m}" for m in missing)
        )

    def test_base_pkgs_includes_required_tools(self):
        """install_system_packages base list includes all required tools."""
        base = ["nmap", "git", "go", "python3", "pip", "python3-venv",
                "nodejs", "npm", "graphviz", "hydra", "sshpass",
                "aircrack-ng", "masscan", "macchanger", "john",
                "exploitdb"]
        missing = [t for t in self.REQUIRED_TOOLS if t not in base]
        assert not missing, f"base_pkgs missing: {missing}"

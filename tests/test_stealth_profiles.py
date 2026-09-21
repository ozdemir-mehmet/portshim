"""Unit tests for skills/site-assessment-pipeline/scripts/engagement-profiles.py."""
import json
import os
import sys
from pathlib import Path

import pytest

# Add the stealth-profiles script directory to sys.path
SCRIPTS_DIR = (
    Path(__file__).resolve().parent.parent
    / "skills"
    / "site-assessment-pipeline"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS_DIR))

# Remove .py extension handling — the module is engagement-profiles.py
# We need to import the module directly; the script name has a hyphen.
# Use importlib.
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "stealth_profiles",
    str(SCRIPTS_DIR / "engagement-profiles.py"),
)
_stealth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_stealth)

# Now we have access to PROFILES, ALL_TOOLS, validate_profile, main
PROFILES = _stealth.PROFILES
ALL_TOOLS = _stealth.ALL_TOOLS
validate_profile = _stealth.validate_profile
main = _stealth.main


# ===========================================================================
# Profile structure validation
# ===========================================================================


class TestProfileStructure:
    """Tests for the PROFILES dictionary structure."""

    def test_all_three_profiles_exist(self):
        """PROFILES contains 'silent-entry', 'surgical', and 'full-assault'."""
        assert "silent-entry" in PROFILES
        assert "surgical" in PROFILES
        assert "full-assault" in PROFILES
        assert len(PROFILES) == 3

    def test_each_profile_has_label_and_description(self):
        """Every profile has 'label' and 'description' keys."""
        for name, prof in PROFILES.items():
            assert "label" in prof, f"{name} missing 'label'"
            assert "description" in prof, f"{name} missing 'description'"
            assert isinstance(prof["label"], str)
            assert isinstance(prof["description"], str)

    def test_each_profile_covers_all_tools(self):
        """Every profile has entries for all ALL_TOOLS."""
        for name, prof in PROFILES.items():
            for tool in ALL_TOOLS:
                assert tool in prof, f"{name} missing tool '{tool}'"


# ===========================================================================
# Silent Entry profile
# ===========================================================================


class TestSilentEntry:
    """Tests for the 'silent-entry' profile."""

    @pytest.fixture
    def profile(self):
        return PROFILES["silent-entry"]

    def test_label(self, profile):
        assert profile["label"] == "Silent Entry"

    def test_nmap_flags(self, profile):
        assert "-T1" in profile["nmap"]
        assert "--scan-delay 30s" in profile["nmap"]
        assert "--max-rate 5" in profile["nmap"]

    def test_httpx_flags(self, profile):
        assert profile["httpx"] == "-threads 1 -delay 30 -timeout 10"

    def test_nuclei_disabled(self, profile):
        """Silent-entry should have nuclei DISABLED."""
        assert profile["nuclei"] == "DISABLED"

    def test_brute_force_disabled(self, profile):
        """Silent-entry should have brute_force set to False."""
        assert profile["brute_force"] is False

    def test_neuroploit_recon_only(self, profile):
        assert profile["neuroploit"] == "--mode recon-only"

    def test_guardian_flags(self, profile):
        assert profile["guardian"] == "recon"

    def test_ssh_keys_only(self, profile):
        assert profile["ssh"] == "keys-only"


# ===========================================================================
# Surgical profile
# ===========================================================================


class TestSurgical:
    """Tests for the 'surgical' profile."""

    @pytest.fixture
    def profile(self):
        return PROFILES["surgical"]

    def test_label(self, profile):
        assert profile["label"] == "Surgical"

    def test_nmap_flags(self, profile):
        assert "-T3" in profile["nmap"]
        assert "-sS" in profile["nmap"]
        assert "--max-rate 200" in profile["nmap"]

    def test_httpx_flags(self, profile):
        assert profile["httpx"] == "-threads 5 -timeout 8"

    def test_nuclei_flags(self, profile):
        assert "-severity critical,high" in profile["nuclei"]
        assert "-rl 3" in profile["nuclei"]

    def test_brute_force_common_only(self, profile):
        assert profile["brute_force"] == "common-only"

    def test_neuroploit_flags(self, profile):
        assert profile["neuroploit"] == "--vote-n 1 --agents vuln --agents recon"

    def test_guardian_flags(self, profile):
        assert profile["guardian"] == "web_pentest"

    def test_ssh_keys_and_known(self, profile):
        assert profile["ssh"] == "keys-and-known"


# ===========================================================================
# Full Assault profile
# ===========================================================================


class TestFullAssault:
    """Tests for the 'full-assault' profile."""

    @pytest.fixture
    def profile(self):
        return PROFILES["full-assault"]

    def test_label(self, profile):
        assert profile["label"] == "Full Assault"

    def test_nmap_flags(self, profile):
        assert "-T5" in profile["nmap"]
        assert "-A" in profile["nmap"]
        assert "--script vuln" in profile["nmap"]
        assert "--min-rate 500" in profile["nmap"]

    def test_httpx_flags(self, profile):
        assert profile["httpx"] == "-threads 50 -timeout 5"

    def test_nuclei_flags(self, profile):
        assert "-severity critical,high,medium,low" in profile["nuclei"]
        assert "-rl 10" in profile["nuclei"]
        assert "-c 10" in profile["nuclei"]

    def test_brute_force_enabled(self, profile):
        """Full-assault should have brute_force set to True."""
        assert profile["brute_force"] is True

    def test_neuroploit_flags(self, profile):
        assert profile["neuroploit"] == "--vote-n 3"

    def test_guardian_flags(self, profile):
        assert profile["guardian"] == "full_vuln_scan"

    def test_ssh_all(self, profile):
        assert profile["ssh"] == "all"


# ===========================================================================
# validate_profile tests
# ===========================================================================


class TestValidateProfile:
    """Tests for validate_profile()."""

    def test_valid_silent_entry(self):
        """validate_profile returns dict for 'silent-entry'."""
        result = validate_profile("silent-entry")
        assert result["label"] == "Silent Entry"

    def test_valid_surgical(self):
        """validate_profile returns dict for 'surgical'."""
        result = validate_profile("surgical")
        assert result["label"] == "Surgical"

    def test_valid_full_assault(self):
        """validate_profile returns dict for 'full-assault'."""
        result = validate_profile("full-assault")
        assert result["label"] == "Full Assault"

    def test_unknown_profile_raises_system_exit(self):
        """validate_profile raises SystemExit for unknown profile names."""
        with pytest.raises(SystemExit) as exc_info:
            validate_profile("stealth-mode")
        assert exc_info.value.code == 1

    def test_unknown_profile_prints_error_message(self, capsys):
        """validate_profile prints helpful error message for unknown profile."""
        with pytest.raises(SystemExit):
            validate_profile("bogus-profile")
        captured = capsys.readouterr()
        assert "Unknown profile" in captured.err
        assert "bogus-profile" in captured.err


# ===========================================================================
# main() — profile + all tools output
# ===========================================================================


class TestMainAllTools:
    """Tests for main() when outputting all tools for a profile."""

    def test_silent_entry_outputs_env_vars(self, capsys, monkeypatch):
        """main('silent-entry') outputs PORTSHIM_* env vars."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "silent-entry"])
        main()
        captured = capsys.readouterr()
        assert "Profile: Silent Entry" in captured.out
        assert "PORTSHIM_NMAP_FLAGS" in captured.out
        assert "PORTSHIM_NUCLEI=DISABLED" in captured.out
        assert "PORTSHIM_NUCLEI_DISABLED=true" in captured.out
        assert "PORTSHIM_BRUTE_FORCE_ENABLED=false" in captured.out

    def test_full_assault_outputs_env_vars(self, capsys, monkeypatch):
        """main('full-assault') outputs PORTSHIM_* env vars with full flags."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "full-assault"])
        main()
        captured = capsys.readouterr()
        assert "Profile: Full Assault" in captured.out
        assert "-T5" in captured.out
        assert "PORTSHIM_BRUTE_FORCE_ENABLED=true" in captured.out
        assert "PORTSHIM_NUCLEI_FLAGS" in captured.out

    def test_surgical_outputs_env_vars(self, capsys, monkeypatch):
        """main('surgical') outputs PORTSHIM_* env vars."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "surgical"])
        main()
        captured = capsys.readouterr()
        assert "Profile: Surgical" in captured.out
        assert "PORTSHIM_NMAP_FLAGS" in captured.out
        assert "PORTSHIM_HTTPX_FLAGS" in captured.out


# ===========================================================================
# main() — single tool output
# ===========================================================================


class TestMainSingleTool:
    """Tests for main() when requesting a single tool's flags."""

    def test_nmap_flag_silent_entry(self, capsys, monkeypatch):
        """main('silent-entry', 'nmap') outputs just the nmap flag string."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "silent-entry", "nmap"])
        main()
        captured = capsys.readouterr()
        assert "-T1" in captured.out
        assert "--scan-delay 30s" in captured.out

    def test_nuclei_silent_entry_exits_2(self, capsys, monkeypatch):
        """main('silent-entry', 'nuclei') exits 2 with 'DISABLED' output."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "silent-entry", "nuclei"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert captured.out.strip() == "DISABLED"

    def test_brute_force_false_outputs_false(self, capsys, monkeypatch):
        """main('silent-entry', 'brute_force') outputs 'false'."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "silent-entry", "brute_force"])
        main()
        captured = capsys.readouterr()
        assert captured.out.strip() == "false"

    def test_brute_force_true_outputs_true(self, capsys, monkeypatch):
        """main('full-assault', 'brute_force') outputs 'true'."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "full-assault", "brute_force"])
        main()
        captured = capsys.readouterr()
        assert captured.out.strip() == "true"

    def test_unknown_tool_raises_system_exit(self, capsys, monkeypatch):
        """main('surgical', 'unknown-tool') raises SystemExit(1)."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "surgical", "unknown-tool"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown tool" in captured.err

    def test_all_tools_output_correct_flags(self, capsys, monkeypatch):
        """Every tool in ALL_TOOLS produces non-empty output for surgical."""
        for tool in ALL_TOOLS:
            monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "surgical", tool])
            try:
                main()
            except SystemExit:
                pass
            captured = capsys.readouterr()
            # brute_force outputs 'true'/'false'
            if tool == "brute_force":
                assert captured.out.strip() in ("true", "false", "common-only")
            else:
                assert len(captured.out.strip()) > 0, f"No output for tool {tool}"


# ===========================================================================
# --list mode
# ===========================================================================


class TestListMode:
    """Tests for the --list output mode."""

    def test_list_outputs_all_profiles(self, capsys, monkeypatch):
        """--list outputs all three profiles with tool entries."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--list"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "silent-entry:" in captured.out
        assert "surgical:" in captured.out
        assert "full-assault:" in captured.out

    def test_list_outputs_tools_for_each_profile(self, capsys, monkeypatch):
        """--list includes tool lines for each profile."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--list"])
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        assert "nmap:" in captured.out
        assert "httpx:" in captured.out
        assert "nuclei:" in captured.out
        assert "neuroploit:" in captured.out
        assert "guardian:" in captured.out
        assert "brute_force:" in captured.out
        assert "ssh:" in captured.out

    def test_list_excludes_label_and_description(self, capsys, monkeypatch):
        """--list output does NOT contain raw label/description strings as tools."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--list"])
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        # "label:" and "description:" should not appear as top-level tool entries
        lines = captured.out.splitlines()
        for line in lines:
            stripped = line.strip()
            if ":" in stripped:
                prefix = stripped.split(":")[0].strip()
                assert prefix not in ("label", "description"), (
                    f"'label'/'description' leaked into --list output: {line}"
                )


# ===========================================================================
# --json mode
# ===========================================================================


class TestJsonMode:
    """Tests for the --json output mode."""

    def test_json_outputs_valid_json(self, capsys, monkeypatch):
        """--json outputs valid JSON string."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--json"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, dict)

    def test_json_contains_all_three_profiles(self, capsys, monkeypatch):
        """--json output contains all three profile keys."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--json"])
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "silent-entry" in data
        assert "surgical" in data
        assert "full-assault" in data
        assert len(data) == 3

    def test_json_profile_structure(self, capsys, monkeypatch):
        """Each profile in JSON has label and all tool keys."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--json"])
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        for name, prof in data.items():
            assert "label" in prof
            assert "description" in prof
            for tool in ALL_TOOLS:
                assert tool in prof, f"JSON profile {name} missing tool {tool}"

    def test_json_silent_entry_values(self, capsys, monkeypatch):
        """JSON output has correct silent-entry values."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--json"])
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        se = data["silent-entry"]
        assert se["nuclei"] == "DISABLED"
        assert se["brute_force"] is False

    def test_json_full_assault_values(self, capsys, monkeypatch):
        """JSON output has correct full-assault values."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--json"])
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        fa = data["full-assault"]
        assert fa["brute_force"] is True
        assert "-T5" in fa["nmap"]


# ===========================================================================
# --help / -h modes
# ===========================================================================


class TestHelpMode:
    """Tests for the --help and -h output modes."""

    def test_help_outputs_docstring(self, capsys, monkeypatch):
        """--help prints the module docstring."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "--help"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "engagement-profiles.py" in captured.out
        assert "loudest" in captured.out

    def test_short_help(self, capsys, monkeypatch):
        """-h also prints help."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py", "-h"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Available profiles:" in captured.out
        assert "silent-entry" in captured.out
        assert "surgical" in captured.out
        assert "full-assault" in captured.out

    def test_no_args_shows_help(self, capsys, monkeypatch):
        """No arguments prints help and exits 0."""
        monkeypatch.setattr(sys, "argv", ["engagement-profiles.py"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Available profiles:" in captured.out


# ===========================================================================
# Cross-profile consistency checks
# ===========================================================================


class TestCrossProfileConsistency:
    """Tests that verify consistency across all profiles."""

    def test_all_profiles_have_same_tool_set(self):
        """Every profile has exactly the same set of tool keys."""
        ref_keys = set(PROFILES["silent-entry"].keys())
        for name, prof in PROFILES.items():
            assert set(prof.keys()) == ref_keys, (
                f"Profile '{name}' has different keys: {set(prof.keys()) ^ ref_keys}"
            )

    def test_nuclei_only_disabled_in_silent_entry(self):
        """Only silent-entry should have nuclei='DISABLED'."""
        assert PROFILES["silent-entry"]["nuclei"] == "DISABLED"
        assert PROFILES["surgical"]["nuclei"] != "DISABLED"
        assert PROFILES["full-assault"]["nuclei"] != "DISABLED"

    def test_brute_force_escalation(self):
        """Brute force escalation: silent=False, surgical=common-only, full=True."""
        assert PROFILES["silent-entry"]["brute_force"] is False
        assert PROFILES["surgical"]["brute_force"] == "common-only"
        assert PROFILES["full-assault"]["brute_force"] is True

    def test_thread_counts_escalate(self):
        """Thread counts escalate from silent to full-assault."""
        # httpx threads
        assert "1" in PROFILES["silent-entry"]["httpx"]
        assert "5" in PROFILES["surgical"]["httpx"]
        assert "50" in PROFILES["full-assault"]["httpx"]

    def test_nmap_timing_escalates(self):
        """Nmap timing templates escalate: -T1 -> -T3 -> -T5."""
        assert "-T1" in PROFILES["silent-entry"]["nmap"]
        assert "-T3" in PROFILES["surgical"]["nmap"]
        assert "-T5" in PROFILES["full-assault"]["nmap"]

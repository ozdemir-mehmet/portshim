"""Unit tests for scripts/sync_knowledge.py."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
import yaml

# Add the scripts directory to sys.path so we can import sync_knowledge
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import sync_knowledge as sk


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_SOURCES = {
    "sources": [
        {
            "repo": "projectdiscovery/nuclei-templates",
            "branch": "main",
            "last_synced_commit": "abc123def456",
            "extracted": [
                {"path": "cves/2024/CVE-2024-1234.yaml", "maps_to": "references/cve-2024-1234.yaml"},
                {"path": "cves/2024/CVE-2024-5678.yaml", "maps_to": "references/cve-2024-5678.yaml"},
            ],
            "notes": "Nuclei CVE templates",
        },
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "branch": "master",
            "last_synced_commit": None,  # Never synced
            "extracted": [
                {"path": "Upload Insecure Files/Picture XML/README.md", "maps_to": "references/xxe-readme.md"},
            ],
            "notes": "XXE payloads",
        },
    ]
}

LATEST_COMMIT_RESPONSE = {
    "sha": "def789abc001",
    "commit": {
        "committer": {
            "date": "2025-06-15T10:30:00Z",
        },
    },
}


@pytest.fixture
def sample_sources_dict():
    """Return a copy of the sample sources dict."""
    return json.loads(json.dumps(SAMPLE_SOURCES))


@pytest.fixture
def skill_dir(tmp_path):
    """Create a temporary skill directory with sources.yaml."""
    skill = tmp_path / "test-skill"
    skill.mkdir()
    sources_file = skill / "sources.yaml"
    with open(sources_file, "w") as f:
        yaml.dump(SAMPLE_SOURCES, f)
    return skill


@pytest.fixture
def skill_dir_no_yaml(tmp_path):
    """Create a temporary skill directory without sources.yaml."""
    skill = tmp_path / "no-sources-skill"
    skill.mkdir()
    return skill


@pytest.fixture
def empty_sources_yaml(tmp_path):
    """Create a skill directory with an empty sources.yaml."""
    skill = tmp_path / "empty-skill"
    skill.mkdir()
    sources_file = skill / "sources.yaml"
    sources_file.write_text("null\n")  # yaml null
    return skill


def _mock_urlopen_response(data, code=200):
    """Create a mock urlopen response object."""
    resp = MagicMock()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    if code == 200:
        resp.read.return_value = json.dumps(data).encode("utf-8")
    else:
        import urllib.error

        error = urllib.error.HTTPError(
            url="https://example.com",
            code=code,
            msg="Error" if code != 403 else "rate limit exceeded",
            hdrs={},
            fp=None,
        )
        resp.__enter__.side_effect = error
    return resp


# ===========================================================================
# parse_sources_yaml / load_sources tests
# ===========================================================================


class TestLoadSources:
    """Tests for load_sources()."""

    def test_valid(self, skill_dir):
        """load_sources returns parsed dict for valid sources.yaml."""
        result = sk.load_sources(skill_dir)
        assert result is not None
        assert "sources" in result
        assert len(result["sources"]) == 2
        assert result["sources"][0]["repo"] == "projectdiscovery/nuclei-templates"

    def test_empty(self, empty_sources_yaml):
        """load_sources returns None for yaml-null content."""
        result = sk.load_sources(empty_sources_yaml)
        assert result is None

    def test_missing_file(self, skill_dir_no_yaml):
        """load_sources returns None when sources.yaml is absent."""
        result = sk.load_sources(skill_dir_no_yaml)
        assert result is None

    def test_empty_sources_list(self, tmp_path):
        """load_sources returns dict with empty sources list."""
        skill = tmp_path / "empty-list-skill"
        skill.mkdir()
        sources_file = skill / "sources.yaml"
        sources_file.write_text("sources: []\n")
        result = sk.load_sources(skill)
        assert result == {"sources": []}


# ===========================================================================
# save_sources / write_reference_updates_sources_yaml tests
# ===========================================================================


class TestSaveSources:
    """Tests for save_sources()."""

    def test_save_writes_new_commit(self, skill_dir, sample_sources_dict):
        """save_sources writes updated last_synced_commit to sources.yaml."""
        sample_sources_dict["sources"][0]["last_synced_commit"] = "new_sha_999"
        sk.save_sources(skill_dir, sample_sources_dict)

        # Re-read and verify
        reloaded = sk.load_sources(skill_dir)
        assert reloaded["sources"][0]["last_synced_commit"] == "new_sha_999"

    def test_save_preserves_structure(self, skill_dir, sample_sources_dict):
        """save_sources preserves full YAML structure after round-trip."""
        sk.save_sources(skill_dir, sample_sources_dict)
        reloaded = sk.load_sources(skill_dir)
        assert reloaded == sample_sources_dict

    def test_save_creates_new_file(self, tmp_path):
        """save_sources creates sources.yaml when it doesn't exist."""
        skill = tmp_path / "new-skill"
        skill.mkdir()
        data = {"sources": []}
        sk.save_sources(skill, data)

        sources_file = skill / "sources.yaml"
        assert sources_file.exists()
        reloaded = sk.load_sources(skill)
        assert reloaded == data


# ===========================================================================
# github_get tests
# ===========================================================================


class TestGithubGet:
    """Tests for github_get()."""

    def test_success(self):
        """github_get returns parsed JSON on 200."""
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_urlopen_response(LATEST_COMMIT_RESPONSE, 200)
            result = sk.github_get("https://api.github.com/repos/x/y/commits/main")
            assert result == LATEST_COMMIT_RESPONSE

    def test_http_404(self):
        """github_get returns None on 404."""
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_urlopen_response({}, 404)
            result = sk.github_get("https://api.github.com/repos/x/y/commits/nonexistent")
            assert result is None

    def test_rate_limit_403(self, capsys):
        """github_get returns None and prints stderr on 403 (rate limit)."""
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_urlopen_response({}, 403)
            result = sk.github_get("https://api.github.com/repos/x/y/commits/main")
            assert result is None
        captured = capsys.readouterr()
        assert "HTTP 403" in captured.err

    def test_rate_limit_429(self, capsys):
        """github_get returns None and prints stderr on 429 (rate limit)."""
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_urlopen_response({}, 429)
            result = sk.github_get("https://api.github.com/repos/x/y/commits/main")
            assert result is None
        captured = capsys.readouterr()
        assert "HTTP 429" in captured.err

    def test_with_token(self):
        """github_get sends Authorization header when token provided."""
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_urlopen_response(LATEST_COMMIT_RESPONSE, 200)
            sk.github_get("https://api.github.com/repos/x/y/commits/main", token="ghp_test123")
            # Verify the Request was built with Authorization
            call_args = mock_urlopen.call_args
            request = call_args[0][0]
            assert request.get_header("Authorization") == "Bearer ghp_test123"

    def test_connection_error(self, capsys):
        """github_get returns None on URLError."""
        import urllib.error

        with patch("sync_knowledge.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
            result = sk.github_get("https://api.github.com/repos/x/y/commits/main")
            assert result is None
        captured = capsys.readouterr()
        assert "Connection error" in captured.err


# ===========================================================================
# fetch_file / fetch_raw tests
# ===========================================================================


class TestFetchRaw:
    """Tests for fetch_raw()."""

    def test_success(self):
        """fetch_raw returns file content on 200."""
        fake_content = "## CVE-2024-1234\nThis is a test template."
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            resp.read.return_value = fake_content.encode("utf-8")
            mock_urlopen.return_value = resp

            result = sk.fetch_raw("owner/repo", "abc123", "path/to/file.yaml")
            assert result == fake_content

    def test_404(self, capsys):
        """fetch_raw returns None and prints stderr on 404."""
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _mock_urlopen_response({}, 404)
            result = sk.fetch_raw("owner/repo", "bad_sha", "missing/file.md")
            assert result is None
        captured = capsys.readouterr()
        assert "File not found upstream" in captured.err
        assert "HTTP 404" in captured.err

    def test_unicode_content(self):
        """fetch_raw handles UTF-8 content correctly."""
        fake_content = "# Payloads\n• XXE payload\n• SQLi payload"
        with patch("sync_knowledge.urlopen") as mock_urlopen:
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            resp.read.return_value = fake_content.encode("utf-8")
            mock_urlopen.return_value = resp

            result = sk.fetch_raw("owner/repo", "abc123", "readme.md")
            assert result == fake_content
            assert "• XXE payload" in result


# ===========================================================================
# commit_comparison tests (via sync_skill)
# ===========================================================================


class TestCommitComparison:
    """Tests for commit comparison logic within sync_skill()."""

    @patch("sync_knowledge.time.sleep", return_value=None)
    @patch("sync_knowledge.fetch_raw")
    @patch("sync_knowledge.github_get")
    def test_newer_commit_triggers_sync(self, mock_github_get, mock_fetch_raw, mock_sleep, tmp_path):
        """When upstream has a newer commit, sync happens and files are written."""
        mock_github_get.return_value = LATEST_COMMIT_RESPONSE
        mock_fetch_raw.return_value = "# New content"

        # Override SKILLS_DIR to use tmp_path
        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "test-skill"
            skill_dir.mkdir()
            sources_file = skill_dir / "sources.yaml"
            # last_synced_commit is OLDER than LATEST_COMMIT_RESPONSE sha
            sample = json.loads(json.dumps(SAMPLE_SOURCES))
            sample["sources"][0]["last_synced_commit"] = "abc123def456"
            with open(sources_file, "w") as f:
                yaml.dump(sample, f)

            result = sk.sync_skill("test-skill", dry_run=False)
            assert result is True  # changed = True
            # Check that fetch_raw was called for extracted files
            assert mock_fetch_raw.call_count > 0

    @patch("sync_knowledge.time.sleep", return_value=None)
    @patch("sync_knowledge.fetch_raw")
    @patch("sync_knowledge.github_get")
    def test_same_commit_skips_sync(self, mock_github_get, mock_fetch_raw, mock_sleep, tmp_path):
        """When upstream commit matches last_synced_commit, sync is skipped."""
        mock_github_get.return_value = LATEST_COMMIT_RESPONSE
        mock_fetch_raw.return_value = "# Should not be fetched"

        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "test-skill"
            skill_dir.mkdir()
            sources_file = skill_dir / "sources.yaml"
            # last_synced_commit matches LATEST_COMMIT_RESPONSE
            sample = json.loads(json.dumps(SAMPLE_SOURCES))
            sample["sources"][0]["last_synced_commit"] = LATEST_COMMIT_RESPONSE["sha"]
            with open(sources_file, "w") as f:
                yaml.dump(sample, f)

            result = sk.sync_skill("test-skill", dry_run=False)
            # Only the second source (no last_synced_commit) will sync
            mock_fetch_raw.assert_called_once()  # only for the second source
            assert mock_fetch_raw.call_count == 1

    @patch("sync_knowledge.time.sleep", return_value=None)
    @patch("sync_knowledge.fetch_raw")
    @patch("sync_knowledge.github_get")
    def test_older_commit_still_syncs(self, mock_github_get, mock_fetch_raw, mock_sleep, tmp_path, capsys):
        """When last_synced is different (older conceptually), sync still triggers."""
        mock_github_get.return_value = {
            "sha": "aaaa00000001",
            "commit": {"committer": {"date": "2024-01-01T00:00:00Z"}},
        }
        mock_fetch_raw.return_value = "# Content"

        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "test-skill"
            skill_dir.mkdir()
            sources_file = skill_dir / "sources.yaml"
            sample = json.loads(json.dumps(SAMPLE_SOURCES))
            sample["sources"][0]["last_synced_commit"] = "older_commit_sha"
            with open(sources_file, "w") as f:
                yaml.dump(sample, f)

            result = sk.sync_skill("test-skill", dry_run=False)
            assert result is True
            captured = capsys.readouterr()
            # Should show the pinned commit and then sync
            assert "Pinned:" in captured.out
            assert "Synced:" in captured.out

    @patch("sync_knowledge.time.sleep", return_value=None)
    @patch("sync_knowledge.fetch_raw")
    @patch("sync_knowledge.github_get")
    def test_dry_run_no_writes(self, mock_github_get, mock_fetch_raw, mock_sleep, tmp_path):
        """sync_skill in dry-run mode does not write files or call fetch_raw."""
        mock_github_get.return_value = LATEST_COMMIT_RESPONSE

        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "test-skill"
            skill_dir.mkdir()
            sources_file = skill_dir / "sources.yaml"
            sample = json.loads(json.dumps(SAMPLE_SOURCES))
            sample["sources"][0]["last_synced_commit"] = "old_sha"
            with open(sources_file, "w") as f:
                yaml.dump(sample, f)

            result = sk.sync_skill("test-skill", dry_run=True)
            assert result is False  # dry-run never sets changed=True
            mock_fetch_raw.assert_not_called()


# ===========================================================================
# sync_skill edge cases
# ===========================================================================


class TestSyncSkillEdgeCases:
    """Edge case tests for sync_skill()."""

    def test_skill_not_found(self, capsys):
        """sync_skill returns False when skill directory doesn't exist."""
        result = sk.sync_skill("nonexistent-skill")
        assert result is False
        captured = capsys.readouterr()
        assert "Skill not found" in captured.err

    def test_no_sources_yaml(self, tmp_path):
        """sync_skill returns False when skill has no sources.yaml."""
        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "bare-skill"
            skill_dir.mkdir()
            result = sk.sync_skill("bare-skill")
            assert result is False

    def test_empty_sources_list(self, tmp_path, capsys):
        """sync_skill returns False when sources list is empty."""
        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "empty-sources"
            skill_dir.mkdir()
            sources_file = skill_dir / "sources.yaml"
            sources_file.write_text("sources: []\n")
            result = sk.sync_skill("empty-sources")
            assert result is False
        captured = capsys.readouterr()
        assert "No sources.yaml or empty sources list" in captured.out

    @patch("sync_knowledge.time.sleep", return_value=None)
    @patch("sync_knowledge.github_get")
    def test_github_api_failure_skips_source(self, mock_github_get, mock_sleep, tmp_path, capsys):
        """When github_get returns None, the source is skipped gracefully."""
        mock_github_get.return_value = None

        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "test-skill"
            skill_dir.mkdir()
            sample = json.loads(json.dumps(SAMPLE_SOURCES))
            sample["sources"][0]["last_synced_commit"] = "old_sha"
            with open(skill_dir / "sources.yaml", "w") as f:
                yaml.dump(sample, f)

            result = sk.sync_skill("test-skill")
            assert result is False  # no changes
        captured = capsys.readouterr()
        assert "Could not fetch latest commit" in captured.out


# ===========================================================================
# find_skills tests
# ===========================================================================


class TestFindSkills:
    """Tests for find_skills()."""

    def test_finds_skills_with_sources(self, tmp_path):
        """find_skills returns skill dirs that have sources.yaml."""
        with patch.object(sk, "SKILLS_DIR", tmp_path):
            (tmp_path / "skill-a").mkdir()
            (tmp_path / "skill-a" / "sources.yaml").write_text("sources: []\n")
            (tmp_path / "skill-b").mkdir()
            (tmp_path / "skill-b" / "sources.yaml").write_text("sources: []\n")
            (tmp_path / "skill-no-sources").mkdir()  # No sources.yaml

            result = sk.find_skills()
            assert sorted(result) == ["skill-a", "skill-b"]

    def test_empty_when_no_skills(self, tmp_path):
        """find_skills returns empty list when no skill dirs exist."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with patch.object(sk, "SKILLS_DIR", empty_dir):
            result = sk.find_skills()
            assert result == []

    def test_returns_nothing_when_skills_dir_missing(self):
        """find_skills returns empty list when SKILLS_DIR doesn't exist."""
        with patch.object(sk, "SKILLS_DIR", Path("/nonexistent/path/xyz")):
            result = sk.find_skills()
            assert result == []


# ===========================================================================
# Integration: full sync_skill flow with file writes
# ===========================================================================


class TestFullSyncFlow:
    """End-to-end sync flow tests."""

    @patch("sync_knowledge.time.sleep", return_value=None)
    @patch("sync_knowledge.fetch_raw")
    @patch("sync_knowledge.github_get")
    def test_sync_writes_files_and_updates_sources(self, mock_github_get, mock_fetch_raw, mock_sleep, tmp_path):
        """Full sync: writes reference files and updates last_synced_commit."""
        fake_content = "# CVE-2024-1234 Template\nseverity: critical"
        mock_github_get.return_value = LATEST_COMMIT_RESPONSE
        mock_fetch_raw.return_value = fake_content

        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "test-skill"
            skill_dir.mkdir()
            sample = json.loads(json.dumps(SAMPLE_SOURCES))
            sample["sources"][0]["last_synced_commit"] = "old_sha"
            with open(skill_dir / "sources.yaml", "w") as f:
                yaml.dump(sample, f)

            result = sk.sync_skill("test-skill")
            assert result is True

            # Verify reference files were written
            ref_file = skill_dir / "references" / "cve-2024-1234.yaml"
            assert ref_file.exists()
            content = ref_file.read_text(encoding="utf-8")
            assert "CVE-2024-1234" in content
            assert "Source:" in content  # header was added
            assert "Synced:" in content

            # Verify sources.yaml was updated
            reloaded = sk.load_sources(skill_dir)
            assert reloaded["sources"][0]["last_synced_commit"] == LATEST_COMMIT_RESPONSE["sha"]
            assert reloaded["sources"][1]["last_synced_commit"] == LATEST_COMMIT_RESPONSE["sha"]

    @patch("sync_knowledge.time.sleep", return_value=None)
    @patch("sync_knowledge.fetch_raw")
    @patch("sync_knowledge.github_get")
    def test_never_synced_source_gets_updated(self, mock_github_get, mock_fetch_raw, mock_sleep, tmp_path):
        """Source with last_synced_commit: None gets synced."""
        mock_github_get.return_value = LATEST_COMMIT_RESPONSE
        mock_fetch_raw.return_value = "# XXE Payloads"

        with patch.object(sk, "SKILLS_DIR", tmp_path):
            skill_dir = tmp_path / "test-skill"
            skill_dir.mkdir()
            # Only the never-synced source
            single_source = {
                "sources": [
                    {
                        "repo": "swisskyrepo/PayloadsAllTheThings",
                        "branch": "master",
                        "last_synced_commit": None,
                        "extracted": [
                            {"path": "XXE/README.md", "maps_to": "references/xxe.md"},
                        ],
                        "notes": "XXE payloads",
                    }
                ]
            }
            with open(skill_dir / "sources.yaml", "w") as f:
                yaml.dump(single_source, f)

            result = sk.sync_skill("test-skill")
            assert result is True
            mock_fetch_raw.assert_called_once_with(
                "swisskyrepo/PayloadsAllTheThings", LATEST_COMMIT_RESPONSE["sha"], "XXE/README.md"
            )

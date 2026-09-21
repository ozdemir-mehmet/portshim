"""
Integration test: knowledge sync live.
Tests sync_knowledge.py against a real GitHub repo.
NOT for CI — requires network. Run manually before engagement.

Usage: pytest tests/integration/test_knowledge_sync_live.py -v -m network
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

# Add scripts dir to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

# Skip unless explicitly requested
pytestmark = pytest.mark.network

TEST_REPO = "NousResearch/hermes-agent"
TEST_FILE = "README.md"


@pytest.fixture
def temp_skill_dir():
    """Create a temporary skill directory with sources.yaml."""
    with tempfile.TemporaryDirectory() as tmp:
        skill_dir = Path(tmp) / "test-skill"
        skill_dir.mkdir()
        refs_dir = skill_dir / "references"
        refs_dir.mkdir()

        sources = {
            "sources": [
                {
                    "repo": TEST_REPO,
                    "branch": "main",
                    "last_synced_commit": None,
                    "extracted": [
                        {"path": TEST_FILE, "maps_to": "references/upstream-readme.md"}
                    ],
                    "notes": "Test repo for integration test",
                }
            ]
        }
        with open(skill_dir / "sources.yaml", "w") as f:
            yaml.dump(sources, f)

        yield skill_dir


def test_sync_fetches_file(temp_skill_dir, monkeypatch):
    """Test that sync_knowledge fetches a file from a real repo."""
    from sync_knowledge import sync_skill, load_sources

    # Override SKILLS_DIR to point at temp dir's parent
    monkeypatch.setattr("sync_knowledge.SKILLS_DIR", temp_skill_dir.parent)
    monkeypatch.setattr("sync_knowledge.RATE_LIMIT_WAIT", 0)  # skip wait in tests

    changed = sync_skill("test-skill", dry_run=False)

    # Verify sources.yaml was updated with a real commit hash
    sources = load_sources(temp_skill_dir)
    assert sources["sources"][0]["last_synced_commit"] is not None
    assert len(sources["sources"][0]["last_synced_commit"]) == 40  # SHA-1

    # Verify reference file was created
    ref_file = temp_skill_dir / "references" / "upstream-readme.md"
    assert ref_file.exists()
    content = ref_file.read_text()
    assert len(content) > 100  # Real README is substantial
    assert "hermes" in content.lower()


def test_sync_skips_when_up_to_date(temp_skill_dir, monkeypatch):
    """Test that re-syncing with same commit skips."""
    from sync_knowledge import sync_skill, load_sources

    monkeypatch.setattr("sync_knowledge.SKILLS_DIR", temp_skill_dir.parent)
    monkeypatch.setattr("sync_knowledge.RATE_LIMIT_WAIT", 0)

    # First sync
    sync_skill("test-skill", dry_run=False)

    # Get the commit we synced to
    sources = load_sources(temp_skill_dir)
    first_commit = sources["sources"][0]["last_synced_commit"]

    # Second sync
    changed = sync_skill("test-skill", dry_run=False)

    # Should NOT have changed (commit is the same)
    sources = load_sources(temp_skill_dir)
    assert sources["sources"][0]["last_synced_commit"] == first_commit


def test_sync_dry_run_does_not_write(temp_skill_dir, monkeypatch):
    """Test that --dry-run doesn't write any files."""
    from sync_knowledge import sync_skill, load_sources

    monkeypatch.setattr("sync_knowledge.SKILLS_DIR", temp_skill_dir.parent)
    monkeypatch.setattr("sync_knowledge.RATE_LIMIT_WAIT", 0)

    sync_skill("test-skill", dry_run=True)

    sources = load_sources(temp_skill_dir)
    assert sources["sources"][0]["last_synced_commit"] is None

    ref_file = temp_skill_dir / "references" / "upstream-readme.md"
    assert not ref_file.exists()

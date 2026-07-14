"""Integration tests: cross-skill consistency checks.

Scans skills/ directory for subdirectories with SKILL.md and validates:
  - sources.yaml exists and is valid YAML
  - Referenced GitHub repos use valid owner/repo format
  - Reports counts of skills with/without sources
"""
import re
from pathlib import Path

import pytest
import yaml

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

# pre-compile the owner/repo pattern: alphanumeric + hyphens/underscores/dots
OWNER_REPO_RE = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9_.]*/[a-zA-Z0-9._-]+$")


# ---------------------------------------------------------------------------
# Discovery helper
# ---------------------------------------------------------------------------
def _discover_skills() -> list[Path]:
    """Return sorted list of subdirectories under skills/ that contain SKILL.md."""
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(
        p.parent for p in SKILLS_DIR.rglob("SKILL.md") if p.is_file()
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestSkillConsistency:
    def test_skills_directory_exists(self):
        assert SKILLS_DIR.is_dir(), f"Skills directory not found at {SKILLS_DIR}"

    def test_at_least_one_skill_found(self):
        skills = _discover_skills()
        assert len(skills) >= 1, f"No SKILL.md found under {SKILLS_DIR}"

    @pytest.mark.parametrize("skill_dir", _discover_skills())
    def test_sources_yaml_exists(self, skill_dir):
        sources_path = skill_dir / "sources.yaml"
        assert sources_path.is_file(), (
            f"{skill_dir.name}: sources.yaml missing"
        )

    @pytest.mark.parametrize("skill_dir", _discover_skills())
    def test_sources_yaml_is_valid(self, skill_dir):
        sources_path = skill_dir / "sources.yaml"
        assert sources_path.is_file(), f"{skill_dir.name}: sources.yaml missing"
        with open(sources_path) as f:
            data = yaml.safe_load(f)
        assert data is not None, f"{skill_dir.name}: sources.yaml empty or invalid"
        assert "sources" in data, f"{skill_dir.name}: sources.yaml missing top-level 'sources' key"
        assert isinstance(data["sources"], list), (
            f"{skill_dir.name}: 'sources' must be a list"
        )

    @pytest.mark.parametrize("skill_dir", _discover_skills())
    def test_referenced_repos_have_valid_format(self, skill_dir):
        sources_path = skill_dir / "sources.yaml"
        if not sources_path.is_file():
            pytest.skip("sources.yaml missing")

        with open(sources_path) as f:
            data = yaml.safe_load(f)
        if not data or "sources" not in data:
            pytest.skip("sources key missing")

        for idx, entry in enumerate(data["sources"]):
            repo = entry.get("repo", "")
            assert OWNER_REPO_RE.match(repo), (
                f"{skill_dir.name}: source #{idx + 1} repo '{repo}' is not"
                f" a valid owner/repo format"
            )

    def test_report_counts_with_and_without_sources(self):
        """Produce report: count of skills with/without sources."""
        all_dirs = sorted(
            d for d in SKILLS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")
        )
        skills_with_md = _discover_skills()

        with_md_count = len(skills_with_md)
        without_md = [d for d in all_dirs if d not in skills_with_md]

        # Among skills WITH SKILL.md, count those with/without sources.yaml
        with_sources = []
        without_sources = []
        for skill_dir in skills_with_md:
            sources = skill_dir / "sources.yaml"
            repo_count = 0
            if sources.is_file():
                with open(sources) as f:
                    data = yaml.safe_load(f)
                if data and isinstance(data.get("sources"), list):
                    repo_count = len(data["sources"])
                    with_sources.append((skill_dir.name, repo_count))
                else:
                    without_sources.append(skill_dir.name)
            else:
                without_sources.append(skill_dir.name)

        # This is informational — we just assert it's runnable
        print(f"\n=== Skill Source Consistency Report ===")
        print(f"Total skill directories:             {len(all_dirs)}")
        print(f"Skills with SKILL.md:                 {with_md_count}")
        print(f"Skills without SKILL.md:              {len(without_md)}")
        if without_md:
            print(f"  (subdirs: {[d.name for d in without_md]})")
        print(f"Skills with sources.yaml & repos:     {len(with_sources)}")
        for name, count in with_sources:
            print(f"  - {name}: {count} repo(s)")
        print(f"Skills missing sources.yaml or empty: {len(without_sources)}")
        for name in without_sources:
            print(f"  - {name}")

        # Basic sanity assertions
        assert with_md_count >= 1, "Expected at least one skill with SKILL.md"
        # Some skills may legitimately have empty sources

    def test_no_duplicate_skill_names(self):
        """Ensure no two subdirectories with SKILL.md share a name (though
        they are in different directories, names should be unique for clarity)."""
        skills = _discover_skills()
        names = [d.name for d in skills]
        assert len(names) == len(set(names)), f"Duplicate skill names: {names}"

    def test_sources_yaml_entries_have_required_fields(self):
        """Each source entry should have at minimum a 'repo' and 'branch' field."""
        for skill_dir in _discover_skills():
            sources_path = skill_dir / "sources.yaml"
            if not sources_path.is_file():
                continue
            with open(sources_path) as f:
                data = yaml.safe_load(f)
            if not data or "sources" not in data:
                continue
            for idx, entry in enumerate(data["sources"]):
                assert "repo" in entry, (
                    f"{skill_dir.name}: source #{idx + 1} missing 'repo'"
                )
                assert "branch" in entry, (
                    f"{skill_dir.name}: source #{idx + 1} missing 'branch'"
                )
                assert isinstance(entry["repo"], str), (
                    f"{skill_dir.name}: source #{idx + 1} 'repo' must be a string"
                )
                assert isinstance(entry["branch"], str), (
                    f"{skill_dir.name}: source #{idx + 1} 'branch' must be a string"
                )

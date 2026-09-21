#!/usr/bin/env python3
"""
check-skill-freshness.py — Report on knowledge source staleness.

Scans all skills with sources.yaml, checks last_synced_commit age,
and reports which skills are fresh, stale, or have never been synced.

Usage:
    python scripts/check-skill-freshness.py           # Report only
    python scripts/check-skill-freshness.py --json     # Machine-readable output
    python scripts/check-skill-freshness.py --max-age 30  # Custom staleness threshold (days)
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_NEVER_SYNCED = "never_synced"
STATUS_NO_SOURCES = "no_sources"


def check_skill(skill_name: str, max_age_days: int = 30) -> dict:
    """Check freshness of a single skill. Returns report dict."""
    skill_path = SKILLS_DIR / skill_name
    sources_file = skill_path / "sources.yaml"

    result = {
        "skill": skill_name,
        "status": STATUS_NO_SOURCES,
        "repos": [],
        "warnings": [],
    }

    if not sources_file.exists():
        return result

    with open(sources_file) as f:
        sources = yaml.safe_load(f)

    if not sources or not sources.get("sources"):
        return result

    now = datetime.now(timezone.utc)
    result["status"] = STATUS_FRESH  # Assume fresh until proven otherwise

    for source in sources["sources"]:
        repo = source["repo"]
        last_commit = source.get("last_synced_commit")

        repo_info = {"repo": repo, "synced": bool(last_commit)}

        if not last_commit:
            result["status"] = STATUS_NEVER_SYNCED
            result["warnings"].append(f"{repo}: never synced (last_synced_commit is null)")
            result["repos"].append(repo_info)
            continue

        # Check file modification time as a freshness proxy.
        # NOTE: This measures when sources.yaml was last written (sync or manual edit),
        # NOT the upstream commit date. An API call would be needed for true freshness.
        try:
            sources_mtime = datetime.fromtimestamp(
                sources_file.stat().st_mtime, tz=timezone.utc
            )
        except OSError as e:
            result["warnings"].append(f"{repo}: cannot stat sources.yaml ({e})")
            result["repos"].append(repo_info)
            continue

        age_days = (now - sources_mtime).days
        repo_info["sources_yaml_age_days"] = age_days
        repo_info["freshness_is_approximate"] = True

        if age_days > max_age_days:
            repo_info["stale"] = True
            result["status"] = STATUS_STALE
            result["warnings"].append(
                f"{repo}: last synced {age_days}d ago (max {max_age_days}d)"
            )
        else:
            repo_info["stale"] = False

        result["repos"].append(repo_info)

    return result


def find_skills() -> list[str]:
    """Find all skill directories."""
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(d.name for d in SKILLS_DIR.iterdir() if d.is_dir())


def main():
    parser = argparse.ArgumentParser(description="Check skill knowledge freshness")
    parser.add_argument("--max-age", type=int, default=30,
                        help="Max age in days before a source is considered stale (default: 30)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    args = parser.parse_args()

    skills = find_skills()
    if not skills:
        print("No skills found.")
        return

    results = [check_skill(name, args.max_age) for name in skills]

    if args.json:
        print(json.dumps(results, indent=2))
        return

    # Human-readable report
    fresh = sum(1 for r in results if r["status"] == STATUS_FRESH)
    stale = sum(1 for r in results if r["status"] == STATUS_STALE)
    never = sum(1 for r in results if r["status"] == STATUS_NEVER_SYNCED)
    none_ = sum(1 for r in results if r["status"] == STATUS_NO_SOURCES)

    print(f"Knowledge Freshness Report ({datetime.now().strftime('%Y-%m-%d')})")
    print(f"  Max age: {args.max_age} days")
    print(f"  Fresh: {fresh}  |  Stale: {stale}  |  Never synced: {never}  |  No sources: {none_}")
    print()

    for r in results:
        icon = {"fresh": "[OK]", "stale": "[!!]", "never_synced": "[--]", "no_sources": "[  ]"}
        print(f"  {icon.get(r['status'], '[??]')} {r['skill']}")
        for w in r["warnings"]:
            print(f"      {w}")

    # Exit code: non-zero if any stale
    if stale > 0:
        print(f"\nWarning: {stale} skill(s) have stale knowledge sources.")
        sys.exit(1)


if __name__ == "__main__":
    main()

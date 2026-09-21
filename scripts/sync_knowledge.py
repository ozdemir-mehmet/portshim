#!/usr/bin/env python3
"""
sync_knowledge.py — Refresh skill knowledge from tracked GitHub repos.

Reads sources.yaml from each skill directory, compares last_synced_commit with
upstream HEAD, and downloads updated reference files into the skill's references/
directory. Pins knowledge to specific commits for auditability.

Usage:
    python scripts/sync_knowledge.py --all          # Sync all skills
    python scripts/sync_knowledge.py --skill guardian-cli  # Sync one skill
    python scripts/sync_knowledge.py --dry-run      # Show what would change
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import yaml

GITHUB_API = "https://api.github.com"
RAW_GITHUB = "https://raw.githubusercontent.com"
SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
RATE_LIMIT_WAIT = 10  # seconds between API calls (60/hr unauthenticated)


def load_sources(skill_path: Path) -> dict | None:
    """Load sources.yaml from a skill directory."""
    sources_file = skill_path / "sources.yaml"
    if not sources_file.exists():
        return None
    with open(sources_file) as f:
        return yaml.safe_load(f)


def save_sources(skill_path: Path, data: dict) -> None:
    """Save updated sources.yaml."""
    sources_file = skill_path / "sources.yaml"
    with open(sources_file, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def github_get(url: str, token: str | None = None) -> dict | list | None:
    """GET a GitHub API endpoint, return parsed JSON."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "portshim"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        print(f"  HTTP {e.code} for {url}", file=sys.stderr)
        return None
    except URLError as e:
        print(f"  Connection error: {e.reason}", file=sys.stderr)
        return None


def fetch_raw(repo: str, commit: str, path: str) -> str | None:
    """Fetch a raw file from GitHub at a specific commit."""
    url = f"{RAW_GITHUB}/{repo}/{commit}/{path}"
    try:
        req = Request(url, headers={"User-Agent": "portshim"})
        with urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        print(f"  File not found upstream: {path} (HTTP {e.code})", file=sys.stderr)
        return None


def sync_skill(skill_name: str, dry_run: bool = False, token: str | None = None) -> bool:
    """Sync a single skill's knowledge sources. Returns True if anything changed."""
    skill_path = SKILLS_DIR / skill_name
    if not skill_path.is_dir():
        print(f"Skill not found: {skill_name} ({skill_path})", file=sys.stderr)
        return False

    sources = load_sources(skill_path)
    if not sources or not sources.get("sources"):
        print(f"  No sources.yaml or empty sources list")
        return False

    changed = False
    for source in sources["sources"]:
        repo = source["repo"]
        branch = source.get("branch", "main")
        last_commit = source.get("last_synced_commit")
        extracted = source.get("extracted", [])
        notes = source.get("notes", repo)

        print(f"  [{repo}] {notes}")

        # Get latest commit on branch
        latest = github_get(f"{GITHUB_API}/repos/{repo}/commits/{branch}", token)
        if not latest:
            print(f"    Could not fetch latest commit — skipping")
            continue

        latest_sha = latest["sha"]
        short_sha = latest_sha[:8]
        commit_date = latest["commit"]["committer"]["date"][:10]
        print(f"    Latest:  {short_sha} ({commit_date})")

        if last_commit:
            print(f"    Pinned:  {last_commit[:8]}")
            if last_commit == latest_sha:
                print(f"    Status:  up to date — nothing to sync")
                continue

        if dry_run:
            print(f"    Status:  WOULD sync ({len(extracted)} files)")
            continue

        # Fetch and write each tracked file
        synced = 0
        for entry in extracted:
            remote_path = entry["path"]
            local_path = entry["maps_to"]

            content = fetch_raw(repo, latest_sha, remote_path)
            if content is None:
                continue

            # Validate path — reject traversal
            resolved = (skill_path / local_path).resolve()
            if not str(resolved).startswith(str(skill_path.resolve())):
                print(f"    ERROR: Path traversal detected in {local_path} — skipping", file=sys.stderr)
                continue

            dest = resolved
            dest.parent.mkdir(parents=True, exist_ok=True)

            # Add source header
            header = (
                f"<!-- Source: https://github.com/{repo}/blob/{latest_sha[:8]}/{remote_path} -->\n"
                f"<!-- Synced: {commit_date} -->\n\n"
            )
            with open(dest, "w", encoding="utf-8") as f:
                f.write(header + content)

            print(f"    Wrote:   {local_path} ({len(content)} chars)")
            synced += 1

        # Update last_synced_commit only if at least one file was synced
        if synced > 0:
            source["last_synced_commit"] = latest_sha
            print(f"    Synced:  {synced}/{len(extracted)} files")
            changed = True
        else:
            print(f"    Synced:  0/{len(extracted)} files (all upstream files returned 404)")

        time.sleep(RATE_LIMIT_WAIT)

    if changed and not dry_run:
        save_sources(skill_path, sources)
        print(f"  Updated sources.yaml")

    return changed


def find_skills() -> list[str]:
    """Find all skill directories that have a sources.yaml."""
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(
        d.name for d in SKILLS_DIR.iterdir()
        if d.is_dir() and (d / "sources.yaml").exists()
    )


def main():
    parser = argparse.ArgumentParser(description="Sync skill knowledge from GitHub repos")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Sync all skills with sources.yaml")
    group.add_argument("--skill", type=str, help="Sync a specific skill by name")
    group.add_argument("--list", action="store_true", help="List all skills with sources.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    parser.add_argument("--token", type=str, help="GitHub personal access token (env: GITHUB_TOKEN)")
    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")

    if args.list:
        skills = find_skills()
        if not skills:
            print("No skills with sources.yaml found.")
            return
        print("Skills with knowledge sources:")
        for name in skills:
            sources = load_sources(SKILLS_DIR / name)
            count = len(sources.get("sources", [])) if sources else 0
            print(f"  {name} ({count} tracked repos)")
        return

    if args.all:
        skills = find_skills()
        if not skills:
            print("No skills with sources.yaml found.")
            return
        print(f"Syncing {len(skills)} skill(s)...")
        total_changed = 0
        for name in skills:
            print(f"\n--- {name} ---")
            if sync_skill(name, dry_run=args.dry_run, token=token):
                total_changed += 1
        print(f"\nDone: {total_changed}/{len(skills)} skill(s) updated.")
    elif args.skill:
        sync_skill(args.skill, dry_run=args.dry_run, token=token)


if __name__ == "__main__":
    main()

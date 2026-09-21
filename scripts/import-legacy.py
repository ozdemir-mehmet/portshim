#!/usr/bin/env python3
"""
import-legacy.py — Import existing findings.json files into scan history DB.

Usage:
    python scripts/import-legacy.py findings.json --engagement acme-2025
    python scripts/import-legacy.py --all-from output/               # Bulk import
    python scripts/import-legacy.py findings.json --engagement X --dry-run
"""

import argparse, json, os, sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_db import ScanDB


def guess_engagement_id(path):
    """Try to extract engagement ID from filename or directory."""
    p = Path(path)
    # Try findings filename patterns
    name = p.stem
    if "findings" in name.lower():
        name = name.replace("findings", "").replace("-", " ").replace("_", " ").strip()
        if name:
            return name.replace(" ", "-").lower()
    # Use parent directory name
    parent = p.parent.name
    if parent and parent not in [".", "output", "reports"]:
        return parent.lower().replace(" ", "-")
    # Fallback: timestamp
    return f"import-{datetime.now().strftime('%Y%m%d-%H%M')}"


def main():
    parser = argparse.ArgumentParser(description="Import legacy findings into scan history DB")
    parser.add_argument("findings", nargs="?", help="Path to findings.json")
    parser.add_argument("--engagement", "-e", help="Engagement ID (auto-detected if omitted)")
    parser.add_argument("--client", "-c", help="Client name")
    parser.add_argument("--all-from", metavar="DIR", help="Bulk import all findings.json files under directory")
    parser.add_argument("--dry-run", action="store_true", help="Preview without saving")
    args = parser.parse_args()

    if args.all_from:
        root = Path(args.all_from)
        json_files = list(root.rglob("*findings*.json")) + list(root.rglob("findings.json"))
        if not json_files:
            print(f"No findings.json files found under {root}")
            sys.exit(1)
        print(f"Found {len(json_files)} findings file(s)")
        for jf in json_files:
            eid = guess_engagement_id(jf)
            print(f"  {jf} → engagement '{eid}'")
        if args.dry_run:
            return
        db = ScanDB()
        for jf in json_files:
            eid = guess_engagement_id(jf)
            with open(jf) as f:
                findings = json.load(f)
            db.save_engagement(eid, "unknown")
            db.save_findings(eid, findings)
            db.complete_engagement(eid, len(findings))
            print(f"  Imported: {eid} ({len(findings)} findings)")
        print(f"\nDone. {len(json_files)} engagement(s) imported.")
        return

    if not args.findings:
        parser.print_help()
        sys.exit(1)

    eid = args.engagement or guess_engagement_id(args.findings)
    with open(args.findings) as f:
        findings = json.load(f)

    if args.dry_run:
        print(f"[DRY RUN] Would import:")
        print(f"  File:       {args.findings}")
        print(f"  Engagement: {eid}")
        print(f"  Findings:   {len(findings)}")
        return

    db = ScanDB()
    db.save_engagement(eid, args.client, "imported")
    db.save_findings(eid, findings)
    db.complete_engagement(eid, len(findings))
    print(f"Imported: {eid} ({len(findings)} findings)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
save-to-db.py — Save engagement findings to SQLite scan history.

Usage:
    python scripts/save-to-db.py findings.json --engagement acme-july
    python scripts/save-to-db.py findings.json --engagement acme-july --client "Acme Corp"
    python scripts/save-to-db.py findings.json --engagement acme-july --hosts topology.json

Input:
    findings.json  — Phase 4 output (list of finding objects)
    topology.json  — Phase 1 output (host list, optional)

Config:
    PD_DB_PATH env var — path to SQLite file
"""

import argparse, json, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_db import ScanDB


def load_json(path):
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="Save engagement data to scan history DB")
    parser.add_argument("findings", help="Path to findings.json")
    parser.add_argument("--engagement", "-e", required=True, help="Engagement ID (e.g. acme-july-2026)")
    parser.add_argument("--client", "-c", help="Client name")
    parser.add_argument("--hosts", "-H", help="Path to topology.json (optional)")
    parser.add_argument("--stealth", default="surgical", help="Stealth profile used")
    parser.add_argument("--mode", default="hybrid", help="LLM mode used")
    parser.add_argument("--target", help="Target CIDR")
    parser.add_argument("--dry-run", action="store_true", help="Preview without saving")
    args = parser.parse_args()

    findings = load_json(args.findings)
    hosts = load_json(args.hosts) if args.hosts else []

    # Severity counts
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = (f.get("severity") or "").lower()
        if s in sev:
            sev[s] += 1

    if args.dry_run:
        print(f"[DRY RUN] Would save to DB:")
        print(f"  Engagement: {args.engagement}")
        print(f"  Client:     {args.client or '(none)'}")
        print(f"  Findings:   {len(findings)}")
        print(f"  Severity:   C:{sev['critical']} H:{sev['high']} M:{sev['medium']} L:{sev['low']}")
        print(f"  Hosts:      {len(hosts)}")
        return

    db = ScanDB()

    # Save engagement
    db.save_engagement(
        engagement_id=args.engagement,
        client=args.client,
        target_cidr=args.target or "unknown",
        stealth=args.stealth,
        llm_mode=args.mode,
        total_hosts=len(hosts),
    )

    # Save hosts
    if hosts:
        db.save_hosts(args.engagement, hosts)

    # Save findings
    db.save_findings(args.engagement, findings)

    # Complete engagement with counts
    db.complete_engagement(args.engagement, len(findings), **sev)

    print(f"Saved to {db.db_path}:")
    print(f"  Engagement: {args.engagement}")
    print(f"  Findings:   {len(findings)}")
    print(f"  Hosts:      {len(hosts)}")


if __name__ == "__main__":
    main()

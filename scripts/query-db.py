#!/usr/bin/env python3
"""
query-db.py — Query the PortShim scan history database.

Usage:
    python scripts/query-db.py --engagements                     # List all engagements
    python scripts/query-db.py --engagement acme-july            # All findings for one engagement
    python scripts/query-db.py --severity critical               # All critical findings
    python scripts/query-db.py --engagement acme --status open   # Open findings only
    python scripts/query-db.py --compare acme-june acme-july     # Delta between two scans
    python scripts/query-db.py --stats                           # Aggregate metrics
    python scripts/query-db.py --export acme-july --format json  # Export as JSON
"""

import argparse, json, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_db import ScanDB


def main():
    parser = argparse.ArgumentParser(description="Query PortShim scan history")
    parser.add_argument("--engagements", "-l", action="store_true", help="List all engagements")
    parser.add_argument("--engagement", "-e", help="Filter by engagement ID (or partial match)")
    parser.add_argument("--severity", "-s", help="Filter by severity (critical, high, medium, low)")
    parser.add_argument("--status", help="Filter by status (open, fixed, accepted_risk)")
    parser.add_argument("--compare", nargs=2, metavar=("ENG_A", "ENG_B"), help="Compare two engagements")
    parser.add_argument("--stats", action="store_true", help="Show aggregate statistics")
    parser.add_argument("--export", metavar="ENGAGEMENT", help="Export engagement findings as JSON")
    parser.add_argument("--format", default="table", choices=["table", "json"], help="Output format")
    parser.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    args = parser.parse_args()

    db = ScanDB()

    if args.engagements:
        engagements = db.list_engagements()
        if args.format == "json":
            print(json.dumps(engagements, indent=2))
        else:
            print(f"{'ID':<30} {'Client':<20} {'Target':<20} {'Findings':>8} {'Date'}")
            print("-" * 95)
            for e in engagements:
                print(f"{e['id']:<30} {(e['client'] or ''):<20} {e['target_cidr']:<20} {e['findings_count']:>8} {e['started_at'][:10] if e['started_at'] else ''}")
            print(f"\n{len(engagements)} engagement(s)")

    elif args.compare:
        a, b = args.compare
        result = db.compare_engagements(a, b)
        print(f"Comparing {a} → {b}:")
        print(f"  FIXED:       {len(result['fixed'])}")
        print(f"  STILL OPEN:  {len(result['still_open'])}")
        print(f"  NEW:         {len(result['new'])}")
        if result['still_open']:
            print(f"\n  Still open findings:")
            for f in result['still_open'][:10]:
                print(f"    {f['id']:12s} {f.get('severity','?'):10s} {f.get('title','')[:60]}")

    elif args.stats:
        s = db.stats()
        print(f"Total engagements: {s['total_engagements']}")
        print(f"Total findings:    {s['total_findings']}")
        print(f"Fixed:             {s['fixed']}")
        print(f"Fix rate:          {s['fix_rate']}%")
        print(f"\nBy severity:")
        for sev, count in s['severity_counts'].items():
            bar = "█" * min(count // 5, 40) if count > 0 else ""
            print(f"  {sev:<10} {count:>5}  {bar}")

    elif args.export:
        findings = db.query_findings(engagement_id=args.export, limit=10000)
        print(json.dumps(findings, indent=2))

    else:
        findings = db.query_findings(
            engagement_id=args.engagement,
            severity=args.severity,
            status=args.status,
            limit=args.limit,
        )
        if args.format == "json":
            print(json.dumps(findings, indent=2))
        else:
            print(f"{'ID':<12} {'Severity':<10} {'Host':<18} {'Service':<15} {'CVE':<20} {'Status':<12} {'Title'}")
            print("-" * 130)
            for f in findings:
                title = (f.get('title', '') or '')[:50]
                print(f"{f['id']:<12} {f.get('severity','?'):<10} {f.get('host',''):<18} {(f.get('service','') or ''):<15} {(f.get('cve','') or ''):<20} {f.get('status','?'):<12} {title}")
            print(f"\n{len(findings)} finding(s)")


if __name__ == "__main__":
    main()

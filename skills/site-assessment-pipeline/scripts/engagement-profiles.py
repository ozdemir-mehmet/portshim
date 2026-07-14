#!/usr/bin/env python3
"""
engagement-profiles.py — Noise/aggression level profiles for PortShim.

Three named profiles that output correctly configured CLI flags for each tool.
Use before any scanning phase to set the engagement's noise level.

Usage:
    python scripts/engagement-profiles.py <profile> [tool]
    python scripts/engagement-profiles.py silent-entry          # all tools
    python scripts/engagement-profiles.py surgical nmap         # one tool
    python scripts/engagement-profiles.py --list                # list profiles

Profiles (quietest → loudest):
    silent-entry  — IDS-aware, single-thread, 30s delays, no brute force
    surgical      — Rate-limited, targeted, balanced (default)
    full-assault  — Multi-threaded, all agents, fastest/complete — NOT stealth
"""

import sys
import json

PROFILES = {
    "silent-entry": {
        "label": "Silent Entry",
        "description": "IDS-aware, single-thread, 30s probe delay, no brute force, curl-only fingerprinting",
        "nmap": "-T1 -sT --max-retries 1 --max-rtt-timeout 5s --scan-delay 30s --min-rate 1 --max-rate 5",
        "httpx": "-threads 1 -delay 30 -timeout 10",
        "nuclei": "DISABLED",
        "neuroploit": "--mode recon-only",
        "guardian": "recon",
        "brute_force": False,
        "ssh": "keys-only",
    },
    "surgical": {
        "label": "Surgical",
        "description": "Rate-limited SYN, targeted nuclei per service, verified-CVE-only",
        "nmap": "-T3 -sS --max-retries 2 --min-rate 50 --max-rate 200",
        "httpx": "-threads 5 -timeout 8",
        "nuclei": "-severity critical,high -rl 3 -c 3 -timeout 10",
        "neuroploit": "--vote-n 1 --agents vuln --agents recon",
        "guardian": "web_pentest",
        "brute_force": "common-only",
        "ssh": "keys-and-known",
    },
    "full-assault": {
        "label": "Full Assault",
        "description": "Multi-threaded, full nuclei library, all NeuroSploit agents, complete wordlists",
        "nmap": "-T5 -sS -A --script vuln --min-rate 500",
        "httpx": "-threads 50 -timeout 5",
        "nuclei": "-severity critical,high,medium,low -rl 10 -c 10",
        "neuroploit": "--vote-n 3",
        "guardian": "full_vuln_scan",
        "brute_force": True,
        "ssh": "all",
    },
}

ALL_TOOLS = ["nmap", "httpx", "nuclei", "neuroploit", "guardian", "brute_force", "ssh"]


def validate_profile(name: str) -> dict:
    if name not in PROFILES:
        valid = ", ".join(PROFILES.keys())
        print(f"Error: Unknown profile '{name}'. Valid: {valid}", file=sys.stderr)
        sys.exit(1)
    return PROFILES[name]


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h"):
        print(__doc__)
        print("\nAvailable profiles:")
        for name, prof in PROFILES.items():
            print(f"  {name:<16} {prof['description']}")
        sys.exit(0)

    if sys.argv[1] == "--list":
        for name, prof in PROFILES.items():
            print(f"{name}:")
            for tool, flags in prof.items():
                if tool in ("label", "description"):
                    continue
                print(f"  {tool}: {flags}")
        sys.exit(0)

    if sys.argv[1] == "--json":
        print(json.dumps(PROFILES, indent=2))
        sys.exit(0)

    profile = validate_profile(sys.argv[1])
    tool_filter = sys.argv[2] if len(sys.argv) > 2 else None

    if tool_filter:
        if tool_filter not in ALL_TOOLS:
            print(f"Error: Unknown tool '{tool_filter}'. Valid: {', '.join(ALL_TOOLS)}", file=sys.stderr)
            sys.exit(1)
        value = profile.get(tool_filter, "NOT_CONFIGURED")
        if tool_filter == "brute_force":
            if isinstance(value, bool):
                print("true" if value else "false")
            else:
                print(str(value).lower())  # "common-only" etc.
        elif value == "DISABLED":
            print("DISABLED")
            sys.exit(2)  # Non-zero to signal disabled
        else:
            print(value)
    else:
        # Output all tools as shell-compatible env vars
        print(f"# Profile: {profile['label']}")
        print(f"# {profile['description']}")
        for tool in ALL_TOOLS:
            value = profile.get(tool, "")
            if value == "DISABLED":
                print(f"PORTSHIM_{tool.upper()}=DISABLED")
                print(f"export PORTSHIM_{tool.upper()}_DISABLED=true")
            elif isinstance(value, bool):
                print(f"PORTSHIM_{tool.upper()}_ENABLED={'true' if value else 'false'}")
            else:
                print(f"PORTSHIM_{tool.upper()}_FLAGS='{value}'")


if __name__ == "__main__":
    main()

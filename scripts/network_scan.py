#!/usr/bin/env python3
"""
PortShim Network — fast host discovery via masscan with nmap fallback.

masscan performs fast port-aware discovery (only hosts with open ports are
reported). nmap -sn fallback does a true ping sweep finding all live hosts.
Choose masscan for speed, nmap for completeness.

Usage:
    python scripts/network_scan.py --target 192.168.1.0/24
    python scripts/network_scan.py --target 10.0.0.0/8 --ports 22,80,443 --rate 5000
    python scripts/network_scan.py --target 192.168.1.0/24 --scanner nmap
    python scripts/network_scan.py --target 192.168.1.0/24 --dry-run

Output:
    Structured JSON with hosts, ports, scanner used, and timing info.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "outputs"


def check_masscan_available() -> bool:
    """Return True if masscan is on PATH."""
    return shutil.which("masscan") is not None


def run_masscan(
    targets: str,
    ports: str = "1-1000",
    rate: int = 1000,
) -> str | None:
    """Run masscan and return stdout, or None if not installed/failed."""
    cmd = [
        "masscan", targets,
        f"-p{ports}",
        f"--rate={rate}",
        "-oG", "-",  # grepable output to stdout
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None

    if result.returncode != 0:
        return None

    return result.stdout


def parse_masscan_output(output: str) -> dict:
    """Parse masscan -oG (grepable) output into structured JSON.

    Returns {"scanner": "masscan", "hosts": [...]}
    """
    hosts_map = {}

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue

        # Format: Host: 192.168.1.1 () Ports: 80/open/tcp//http///
        if not line.startswith("Host:"):
            continue

        parts = line.split()
        ip = parts[1] if len(parts) > 1 else None
        if not ip:
            continue

        if ip not in hosts_map:
            hosts_map[ip] = {"ip": ip, "ports": []}

        # Parse Ports: 80/open/tcp//http///
        for part in parts:
            if "/" in part and "/open/" in part:
                fields = part.split("/")
                if len(fields) >= 5:
                    try:
                        hosts_map[ip]["ports"].append({
                            "port": int(fields[0]),
                            "state": fields[1],
                            "protocol": fields[2],
                            "service": fields[4] if fields[4] else "unknown",
                        })
                    except (ValueError, IndexError):
                        continue

    return {
        "scanner": "masscan",
        "hosts": sorted(hosts_map.values(), key=lambda h: h["ip"]),
    }


def run_nmap_fast(targets: str) -> str | None:
    """Run nmap ping sweep (-sn) for fast host discovery. Fallback scanner."""
    cmd = ["nmap", "-sn", targets, "-oX", "-"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    return result.stdout


def discover_hosts(
    targets: str,
    scanner: str = "auto",
    ports: str = "1-1000",
    rate: int = 1000,
) -> dict:
    """Run host discovery and return structured JSON result.

    scanner: "masscan", "nmap", or "auto" (prefer masscan, fallback to nmap)
    """
    start_time = time.time()
    used_scanner = scanner

    if scanner == "auto":
        used_scanner = "masscan" if check_masscan_available() else "nmap"

    output = None
    result = None

    if used_scanner == "masscan":
        output = run_masscan(targets, ports=ports, rate=rate)
        if output:
            result = parse_masscan_output(output)
        else:
            used_scanner = "nmap"

    if used_scanner == "nmap" and not result:
        output = run_nmap_fast(targets)
        if output:
            # Parse nmap XML into simple host list
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(output)
                hosts = []
                for host_elem in root.findall(".//host"):
                    addr = host_elem.find("address")
                    if addr is not None:
                        ip = addr.get("addr")
                        status = host_elem.find("status")
                        hosts.append({
                            "ip": ip,
                            "state": status.get("state") if status is not None else "unknown",
                            "ports": [],
                        })
                result = {"scanner": "nmap", "hosts": hosts}
            except ET.ParseError:
                result = {"scanner": "nmap", "hosts": [], "error": "XML parse failed"}

    if not result:
        return {
            "scanner": used_scanner,
            "hosts": [],
            "error": "Scan produced no output",
        }

    elapsed = round(time.time() - start_time, 1)
    result["elapsed_seconds"] = elapsed
    result["scanner"] = used_scanner
    result["timestamp"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    return result


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PortShim Network — fast host discovery (masscan/nmap)",
    )
    parser.add_argument("--target", required=True, help="Target IP/CIDR range")
    parser.add_argument(
        "--scanner", choices=["masscan", "nmap", "auto"], default="auto",
        help="Scanner backend (default: auto)",
    )
    parser.add_argument("--ports", default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("--rate", type=int, default=1000, help="Packets/sec for masscan (default: 1000)")
    parser.add_argument("--output", type=Path, help="Output JSON path (default: auto-generated)")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without scanning")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Scanner selection ──
    if args.scanner == "auto":
        has_masscan = check_masscan_available()
        scanner = "masscan" if has_masscan else "nmap"
    else:
        scanner = args.scanner

    # ── Dry run ──
    if args.dry_run:
        print(f"Target:   {args.target}")
        print(f"Scanner:  {scanner}")
        print(f"Ports:    {args.ports}")
        print(f"Rate:     {args.rate} pps")
        print(f"Output:   {args.output or 'auto-generated'}")
        return 0

    # ── Run scan ──
    result = discover_hosts(
        targets=args.target,
        scanner=args.scanner,
        ports=args.ports,
        rate=args.rate,
    )

    # ── Save output ──
    output_path = args.output or (
        OUTPUT_DIR / f"network-scan-{result['timestamp']}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2))

    host_count = len(result["hosts"])
    print(f"\nScan complete: {host_count} host(s) found via {result['scanner']}")
    print(f"Elapsed: {result['elapsed_seconds']}s")
    print(f"Saved: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

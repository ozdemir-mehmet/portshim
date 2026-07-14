#!/usr/bin/env python3
"""
PortShim Wireless — target selection from scan results.

Loads AP data from a previous scan and lets the user pick which
targets to include in the engagement.

Usage:
    python scripts/wireless_select.py                      # Latest scan, interactive
    python scripts/wireless_select.py --scan-file <path>   # Specific scan file
    python scripts/wireless_select.py --auto               # Auto-select strongest APs
    python scripts/wireless_select.py --auto --max 3       # Auto-select top 3
    python scripts/wireless_select.py --list               # Just list, don't save
    python scripts/wireless_select.py --force              # Same as --auto (agent-friendly)

Output:
    outputs/wireless/targets-{timestamp}.json
    Terminal table of selected access points.
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


# ── Scan file discovery ──


def find_latest_scan() -> Path | None:
    """Find the most recent wireless-aps-*.json file in the output directory."""
    if not OUTPUT_DIR.exists():
        return None
    files = sorted(OUTPUT_DIR.glob("wireless-aps-*.json"), reverse=True)
    return files[0] if files else None


def load_scan(file_path: Path) -> dict:
    """Load and validate a scan results JSON file."""
    with open(file_path) as f:
        data = json.load(f)
    if "access_points" not in data:
        print(f"  {RED}\u2717{RESET} Invalid scan file: missing 'access_points' key")
        sys.exit(1)
    return data


# ── Display ──


def print_ap_table(aps: list[dict], show_index: bool = True):
    """Print a numbered table of access points for selection."""
    if not aps:
        print(f"  {YELLOW}No access points to display.{RESET}")
        return

    # Sort by signal strength (strongest first)
    sorted_aps = sorted(aps, key=lambda a: a.get("signal_dbm") or -999, reverse=True)

    # Column widths
    col_ssid = max(len(a.get("display_ssid", a.get("ssid", ""))) for a in sorted_aps)
    col_ssid = max(col_ssid, 20)
    col_ssid = min(col_ssid, 36)
    col_bssid = 17
    col_ch = 4
    col_enc = max(len(a.get("encryption", "")) for a in sorted_aps)
    col_enc = max(col_enc, 14)
    col_sig = 5

    UL, UR, LL, LR = "\u2554", "\u2557", "\u255a", "\u255d"
    H, V = "\u2550", "\u2551"
    TL, TR = "\u251c", "\u2524"

    if show_index:
        hrule = H * 4 + V + H * col_ssid + V + H * col_bssid + V + H * col_ch + V + H * col_enc + V + H * col_sig + H
        print(f"  {UL}{hrule}{UR}")
        h = (
            f"  {V} {'#':>2} {V} {BOLD}{'SSID':<{col_ssid}}{RESET} {V}"
            f" {BOLD}{'BSSID':<{col_bssid}}{RESET} {V}"
            f" {BOLD}{'CH':>2}{RESET}  {V}"
            f" {BOLD}{'ENC':<{col_enc}}{RESET} {V}"
            f" {BOLD}{'SIG':>3}{RESET}  {V}"
        )
        print(h)
        mrule = "\u2500" * 4 + V + "\u2500" * col_ssid + V + "\u2500" * col_bssid + V + "\u2500" * col_ch + V + "\u2500" * col_enc + V + "\u2500" * col_sig + "\u2500"
        print(f"  {TL}{mrule}{TR}")
    else:
        hrule = H + H * col_ssid + V + H * col_bssid + V + H * col_ch + V + H * col_enc + V + H * col_sig + H
        print(f"  {UL}{hrule}{UR}")
        h = (
            f"  {V} {BOLD}{'SSID':<{col_ssid}}{RESET} {V}"
            f" {BOLD}{'BSSID':<{col_bssid}}{RESET} {V}"
            f" {BOLD}{'CH':>2}{RESET}  {V}"
            f" {BOLD}{'ENC':<{col_enc}}{RESET} {V}"
            f" {BOLD}{'SIG':>3}{RESET}  {V}"
        )
        print(h)
        mrule = "\u2500" + "\u2500" * col_ssid + V + "\u2500" * col_bssid + V + "\u2500" * col_ch + V + "\u2500" * col_enc + V + "\u2500" * col_sig + "\u2500"
        print(f"  {TL}{mrule}{TR}")

    for i, ap in enumerate(sorted_aps):
        ssid = ap.get("display_ssid", ap.get("ssid", ""))
        bssid = ap.get("bssid", "").upper()
        channel = ap.get("channel", "?")
        ch_str = str(channel) if channel is not None else "?"
        encryption = ap.get("encryption", "Unknown")
        sig = ap.get("signal_dbm")

        sig_str = str(sig) if sig is not None else "?"
        sig_colour = (
            GREEN if sig is not None and sig >= -50 else
            YELLOW if sig is not None and sig >= -70 else
            RED if sig is not None else DIM
        )

        idx = f"{i + 1:>2}" if show_index else ""
        if show_index:
            row = (
                f"  {V} {idx} {V} {ssid:<{col_ssid}} {V}"
                f" {bssid:<{col_bssid}} {V}"
                f" {ch_str:>2}  {V}"
                f" {encryption:<{col_enc}} {V}"
                f" {sig_colour}{sig_str:>3}{RESET}  {V}"
            )
        else:
            row = (
                f"  {V} {ssid:<{col_ssid}} {V}"
                f" {bssid:<{col_bssid}} {V}"
                f" {ch_str:>2}  {V}"
                f" {encryption:<{col_enc}} {V}"
                f" {sig_colour}{sig_str:>3}{RESET}  {V}"
            )
        print(row)

    if show_index:
        hrule_bot = H * 4 + V + H * col_ssid + V + H * col_bssid + V + H * col_ch + V + H * col_enc + V + H * col_sig + H
    else:
        hrule_bot = H + H * col_ssid + V + H * col_bssid + V + H * col_ch + V + H * col_enc + V + H * col_sig + H

    print(f"  {LL}{hrule_bot}{LR}")
    print(f"\n  {BOLD}{len(sorted_aps)}{RESET} APs detected")


# ── Selection logic ──


def parse_selection_input(input_str: str, max_idx: int) -> list[int]:
    """Parse user input like '1,3-5,7' into 0-based indices. Returns sorted unique."""
    selected = set()
    parts = [p.strip() for p in input_str.split(",")]
    for part in parts:
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_idx = int(start.strip()) - 1
                end_idx = int(end.strip()) - 1
                lo = max(0, min(start_idx, end_idx))
                hi = min(max(start_idx, end_idx), max_idx - 1)
                selected.update(range(lo, hi + 1))
            except ValueError:
                return []
        else:
            try:
                idx = int(part) - 1
                if 0 <= idx < max_idx:
                    selected.add(idx)
            except ValueError:
                return []
    return sorted(selected)


def auto_select(aps: list[dict], max_count: int = 5) -> list[dict]:
    """Auto-select the strongest APs, preferring unique SSIDs."""
    sorted_aps = sorted(aps, key=lambda a: a.get("signal_dbm") or -999, reverse=True)

    selected = []
    seen_ssids = set()

    for ap in sorted_aps:
        if len(selected) >= max_count:
            break
        ssid = ap.get("ssid", "") or "(hidden)"
        if ssid not in seen_ssids:
            selected.append(ap)
            seen_ssids.add(ssid)

    # Fill remaining slots with strongest duplicates
    for ap in sorted_aps:
        if len(selected) >= max_count:
            break
        if ap not in selected:
            selected.append(ap)

    return selected


# ── Main ──


def main():
    parser = argparse.ArgumentParser(
        description="PortShim Wireless — select target access points from scan results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scan-file", default=None,
        help="Scan results JSON file (default: most recent in outputs/wireless/)",
    )
    parser.add_argument(
        "--file", default=None,
        help="Alias for --scan-file",
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Auto-select strongest APs (non-interactive)",
    )
    parser.add_argument(
        "--max", type=int, default=5,
        help="Maximum targets for auto-select (default: 5)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="Just list APs, don't save a selection file",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Alias for --auto (agent-friendly)",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (default: outputs/wireless/)",
    )

    args = parser.parse_args()

    print(f"\n{BOLD}{RED}\u2666 {RESET}{BOLD}PORTSHIM{RESET} {BOLD}WIRELESS{RESET} {RED}\u2666{RESET}")
    print(f"{CYAN}Target selection{RESET}\n")

    # ── Load scan data ──
    scan_path = args.scan_file or args.file
    if not scan_path:
        latest = find_latest_scan()
        if not latest:
            status("No scan results found", False)
            print(f"  Run '{CYAN}portshim wireless scan{RESET}' first or specify --scan-file")
            print(f"  Expected directory: {OUTPUT_DIR}")
            sys.exit(1)
        scan_path = latest

    scan_file = Path(scan_path)
    if not scan_file.exists():
        status(f"Scan file not found: {scan_file}", False)
        sys.exit(1)

    scan_data = load_scan(scan_file)
    aps = scan_data.get("access_points", [])
    scan_meta = scan_data.get("scan_metadata", {})

    status(f"Loaded scan from {scan_file.name}", True)
    print(f"  Scan time:   {scan_meta.get('timestamp', 'unknown')}")
    print(f"  Interface:   {scan_meta.get('interface', 'unknown')}")
    print(f"  Tool:        {scan_meta.get('tool', 'unknown')}")
    print(f"  Total APs:   {len(aps)}")
    print()

    # ── List only mode ──
    if args.list:
        header("Available Access Points")
        print_ap_table(aps, show_index=True)
        print()
        return

    # ── Determine selection mode ──
    is_auto = args.auto or args.force
    selected_aps = []

    if is_auto:
        selected_aps = auto_select(aps, args.max)
        print(f"  {BOLD}Auto-select{RESET}: picked {len(selected_aps)} APs by signal")
        print()

    else:
        # Interactive selection
        header("Available Access Points")
        print_ap_table(aps, show_index=True)
        print()

        if not aps:
            print(f"  {YELLOW}No APs to select. Run portshim wireless scan first.{RESET}")
            sys.exit(1)

        while True:
            try:
                prompt = f"  Select APs to target (e.g. 1,3-5,7 or 'all') [{BOLD}a{RESET}ll]: "
                user_input = input(prompt).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"\n  {YELLOW}Selection cancelled.{RESET}")
                sys.exit(0)

            if user_input in ("", "a", "all"):
                selected_aps = aps[:]
                break

            indices = parse_selection_input(user_input, len(aps))
            if not indices:
                print(f"  {YELLOW}Invalid selection. Use numbers from the list (e.g. 1,3-5,7).{RESET}")
                continue

            sorted_aps = sorted(aps, key=lambda a: a.get("signal_dbm") or -999, reverse=True)
            selected_aps = [sorted_aps[i] for i in indices]
            break

    # ── Display selection ──
    header("Selected Targets")
    print_ap_table(selected_aps, show_index=False)
    print(f"\n  {BOLD}{len(selected_aps)}{RESET} targets selected")

    # ── Save selection ──
    output_dir = Path(args.output_dir) if args.output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    output_data = {
        "selection_metadata": {
            "timestamp": timestamp,
            "source_scan": scan_file.name,
            "source_scan_timestamp": scan_meta.get("timestamp", ""),
            "selection_mode": "auto" if is_auto else "interactive",
            "total_available": len(aps),
            "total_selected": len(selected_aps),
        },
        "targets": selected_aps,
    }

    json_path = output_dir / f"targets-{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(output_data, f, indent=2)

    status(f"Targets saved to {json_path}", True)
    print()

    # Hint for next step
    print(f"  Next: {CYAN}portshim wireless assess{RESET} to run active assessment")
    print()


if __name__ == "__main__":
    main()

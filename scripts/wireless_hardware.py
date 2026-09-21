#!/usr/bin/env python3
"""
PortShim Wireless — hardware detection and capability reporting.

Detects wireless adapters, checks monitor mode support, identifies
internal vs external interfaces, and picks the best adapter available.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ── Known external USB adapter vendors (for classification) ──
USB_VENDORS_MONITOR = {
    "0bda": "Realtek",   # RTL8812AU, RTL8814AU, RTL88x2BU
    "148f": "Ralink",    # RT5370, RT5572
    "0cf3": "Atheros",   # AR9271, AR7010
    "0846": "NetGear",   # Some NetGear models use RTL/Atheros
    "7392": "Edimax",    # EW-7811Un (RTL8188)
    "0411": "Buffalo",   # Some Buffalo adapters
    "050d": "Belkin",    # Some Belkin adapters
    "07b8": "Abocom",
    "0e66": "Hawking",
    "20b7": "Alfa",      # Alfa AWUS036ACH etc.
}

# Frequency → channel lookup for iw scan output
FREQ_TO_CHANNEL = {
    2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6,
    2442: 7, 2447: 8, 2452: 9, 2457: 10, 2462: 11, 2467: 12,
    2472: 13, 2484: 14,
    5180: 36, 5200: 40, 5220: 44, 5240: 48, 5260: 52, 5280: 56,
    5300: 60, 5320: 64, 5500: 100, 5520: 104, 5540: 108, 5560: 112,
    5580: 116, 5600: 120, 5620: 124, 5640: 128, 5660: 132, 5680: 136,
    5700: 140, 5720: 144, 5745: 149, 5765: 153, 5785: 157, 5805: 161,
    5825: 165,
    5955: 1, 5975: 5, 5995: 9, 6015: 13, 6035: 17, 6055: 21,
    6075: 25, 6095: 29, 6115: 33, 6135: 37, 6155: 41, 6175: 45,
    6195: 49, 6215: 53, 6235: 57, 6255: 61, 6275: 65, 6295: 69,
    6315: 73, 6335: 77, 6355: 81, 6375: 85, 6395: 89, 6415: 93,
    6435: 97, 6455: 101, 6475: 105, 6495: 109, 6515: 113, 6535: 117,
    6555: 121, 6575: 125, 6595: 129, 6615: 133, 6635: 137, 6655: 141,
    6675: 145, 6695: 149, 6715: 153, 6735: 157, 6755: 161, 6775: 165,
    6795: 169, 6815: 173, 6835: 177, 6855: 181, 6875: 185, 6895: 189,
    6915: 193, 6935: 197, 6955: 201, 6975: 205, 6995: 209,
}


# ── Parsing helpers ──

def parse_iw_list_modes(iw_list_output: str) -> list[str]:
    """Extract supported interface modes from 'iw list' output."""
    if not iw_list_output:
        return []
    # Find the "Supported interface modes:" section
    match = re.search(
        r"Supported interface modes:\n((?:\t+ \* \w+.+\n?)*)",
        iw_list_output,
    )
    if not match:
        return []
    modes = []
    for line in match.group(1).splitlines():
        m = re.match(r"\s*\*\s*(\S+)", line)
        if m:
            modes.append(m.group(1))
    return modes


def parse_iw_list_bands(iw_list_output: str) -> list[str]:
    """Extract supported frequency bands from 'iw list' output."""
    if not iw_list_output:
        return []
    bands = set()
    # Find frequency lines:  * NNNN.N MHz [CH]
    for m in re.finditer(r"\*\s+(\d+)\.\d+\s+MHz", iw_list_output):
        freq = int(m.group(1))
        if 2400 <= freq < 2500:
            bands.add("2.4")
        elif 4900 <= freq < 5900:
            bands.add("5")
        elif 5900 <= freq < 7200:
            bands.add("6")
    return sorted(bands)


def classify_adapter_from_uevent(uevent: str) -> dict:
    """
    Parse sysfs uevent to classify adapter as internal or external USB.
    Returns {type, bus, driver}.
    """
    result = {"type": "unknown", "bus": "unknown", "driver": ""}
    if not uevent:
        return result

    driver = ""
    for line in uevent.splitlines():
        if line.startswith("DRIVER="):
            driver = line.split("=", 1)[1]
        elif line.startswith("USB_ID="):
            result["type"] = "external"
            result["bus"] = "usb"
        elif line.startswith("PCI_ID="):
            result["type"] = "internal"
            result["bus"] = "pci"
        elif line.startswith("DEVTYPE=usb_") and result["type"] == "unknown":
            # Some USB adapters lack USB_ID= but have DEVTYPE=usb_device
            # or DEVTYPE=usb_interface with PRODUCT= (e.g. MT7921AU: 0e8d:7961)
            result["type"] = "external"
            result["bus"] = "usb"

    result["driver"] = driver
    return result


def _build_interface_info(
    name: str,
    driver: str,
    iw_list_text: str,
    uevent_text: str,
) -> dict:
    """Combine all info sources into a structured adapter info dict."""
    modes = parse_iw_list_modes(iw_list_text)
    bands = parse_iw_list_bands(iw_list_text)
    uevent_info = classify_adapter_from_uevent(uevent_text)

    has_monitor = "monitor" in modes
    # Packet injection is assumed possible if monitor mode is supported
    # (true for most hardware; aireplay-ng test is the definitive check)
    has_injection = has_monitor

    # Build description
    desc_parts = [driver]
    if uevent_info["type"] == "external":
        desc_parts.append("(external USB)")
    elif uevent_info["type"] == "internal":
        desc_parts.append("(internal)")

    driver_name = driver or uevent_info["driver"]
    return {
        "name": name,
        "driver": driver_name,
        "description": f"{driver_name} {'(external USB)' if uevent_info['type'] == 'external' else '(internal)'}",
        "type": uevent_info["type"],
        "bus": uevent_info["bus"],
        "modes": modes,
        "capabilities": {
            "monitor_mode": has_monitor,
            "packet_injection": has_injection,
            "band_2ghz": "2.4" in bands,
            "band_5ghz": "5" in bands,
            "band_6ghz": "6" in bands,
        },
    }


# ── Runtime detection (calls subprocess) ──

def _run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a command, return result with empty output on failure."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(cmd, 1, "", "")


def detect_interfaces() -> list[str]:
    """List all wireless interface names via iw dev."""
    result = _run(["iw", "dev"])
    if result.returncode != 0:
        return []
    interfaces = []
    for line in result.stdout.splitlines():
        m = re.match(r"\s*Interface\s+(\S+)", line)
        if m:
            interfaces.append(m.group(1))
    return interfaces


def get_iw_list_text() -> str:
    """Get full 'iw list' output."""
    result = _run(["iw", "list"])
    return result.stdout


def get_uevent(iface: str) -> str:
    """Read sysfs uevent for an interface."""
    uevent_path = Path(f"/sys/class/net/{iface}/device/uevent")
    if not uevent_path.exists():
        return ""
    try:
        return uevent_path.read_text()
    except OSError:
        return ""


def get_interface_info(iface: str, iw_list_text: str = "") -> dict:
    """
    Get structured info for a single interface.
    Caches iw_list_text if not provided to avoid repeated subprocess calls.
    """
    if not iw_list_text:
        iw_list_text = get_iw_list_text()
    uevent = get_uevent(iface)
    return _build_interface_info(iface, "", iw_list_text, uevent)


def get_all_interfaces_info() -> list[dict]:
    """Get info for all wireless interfaces on the system."""
    interfaces = detect_interfaces()
    if not interfaces:
        return []
    iw_list_text = get_iw_list_text()
    return [get_interface_info(iface, iw_list_text) for iface in interfaces]


def find_best_adapter(adapters: list[dict]) -> dict | None:
    """
    Pick the best adapter: external+monitor > internal+monitor > anything.
    Returns None if list is empty.
    """
    if not adapters:
        return None

    def score(a: dict) -> int:
        caps = a["capabilities"]
        score = 0
        if caps["monitor_mode"]:
            score += 100
        if caps["packet_injection"]:
            score += 50
        if a.get("type") == "external":
            score += 30
        if caps["band_5ghz"]:
            score += 10
        if caps["band_6ghz"]:
            score += 5
        return score

    return max(adapters, key=score)


# ── External-adapter-only enforcement ──

def get_external_adapters() -> list[dict]:
    """Return only adapters with type == 'external' (USB WiFi adapters)."""
    adapters = get_all_interfaces_info()
    return [a for a in adapters if a.get("type") == "external"]


def require_external_adapter() -> dict:
    """Return the best external USB adapter, or exit with a clear error.

    Never falls back to internal WiFi — wireless operations require an
    external USB adapter for safety (no network disruption).
    """
    externals = get_external_adapters()
    if not externals:
        print(
            "No external USB WiFi adapter detected.\n"
            "Connect an Alfa AWUS036ACH or compatible adapter.\n"
            "Internal WiFi is never used for wireless operations.",
            file=sys.stderr,
        )
        sys.exit(1)
    return find_best_adapter(externals)


# ── Recommendation logic ──

def should_show_recommendation(adapter_info: dict) -> bool:
    """True if we should recommend an external adapter (no monitor mode)."""
    return not adapter_info["capabilities"]["monitor_mode"]


def get_scan_mode(adapter_info: dict) -> str:
    """
    Determine scan mode based on adapter capabilities.
    Returns: 'full' (monitor+injection), 'passive' (monitor only), 'managed' (no monitor)
    """
    caps = adapter_info["capabilities"]
    has_monitor = caps.get("monitor_mode", False)
    has_injection = caps.get("packet_injection", False)
    if has_monitor and has_injection:
        return "full"
    elif caps["monitor_mode"]:
        return "passive"
    return "managed"


# ── Managed-mode scan (iw dev scan) ──

def run_iw_scan(iface: str, duration: int = 10) -> str:
    """Run 'iw dev wlan0 scan' multiple times and return raw output."""
    all_output = []
    try:
        for _ in range(max(1, duration // 2)):
            result = _run(["iw", "dev", iface, "scan"], timeout=5)
            all_output.append(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return "\n".join(all_output)


def parse_iw_scan_output(raw: str) -> list[dict]:
    """
    Parse 'iw dev wlan0 scan' output into structured AP list.
    Returns list of dicts matching wireless_scan.py's format.
    """
    if not raw:
        return []

    aps = []
    # Split on BSS lines
    blocks = re.split(r"^BSS\s+", raw, flags=re.MULTILINE)
    for block in blocks:
        if not block.strip():
            continue
        lines = block.splitlines()

        # First line has BSSID
        bssid_match = re.match(r"([0-9a-fA-F:]{17})", lines[0])
        if not bssid_match:
            continue
        bssid = bssid_match.group(1).upper()

        ssid = ""
        signal_dbm = None
        freq = None
        encryption = "Unknown"

        for line in lines:
            # SSID
            m = re.match(r"\s+SSID:\s*(.*)", line)
            if m:
                ssid = m.group(1).strip()
                continue
            # Frequency
            m = re.match(r"\s+freq:\s+(\d+)", line)
            if m:
                freq = int(m.group(1))
                continue
            # Signal
            m = re.match(r"\s+signal:\s*(-?\d+\.?\d*)", line)
            if m:
                signal_dbm = int(float(m.group(1)))
                continue
            # Encryption (look for known types)
            m = re.search(r"WPA3|WPA2|WPA|WEP", line)
            if m:
                enc_str = m.group(0)
                if "WPA3" in line:
                    encryption = "WPA3-SAE" if "SAE" in line else "WPA3"
                elif "WPA2" in line:
                    encryption = "WPA2-Enterprise" if "802.1X" in line or "MGT" in line else "WPA2-PSK"
                elif "WPA" in line:
                    encryption = "WPA"
                elif "WEP" in line:
                    encryption = "WEP"

        # Map frequency to channel
        channel = None
        if freq:
            channel = FREQ_TO_CHANNEL.get(freq)

        aps.append({
            "ssid": ssid,
            "display_ssid": ssid if ssid else "(hidden)",
            "bssid": bssid,
            "channel": channel,
            "encryption": encryption,
            "signal_dbm": signal_dbm,
        })

    return aps


# ── Network disruption detection and monitor mode management ──


def get_default_route_iface() -> str | None:
    """Return the interface name carrying the default route, or None."""
    result = _run(["ip", "route", "show", "default"])
    if result.returncode != 0 or not result.stdout:
        return None
    m = re.search(r"dev\s+(\S+)", result.stdout)
    return m.group(1) if m else None


def get_current_ssid(iface: str) -> str | None:
    """Get the SSID the interface is currently associated with, or None."""
    if not iface:
        return None
    result = _run(["iw", "dev", iface, "link"])
    if result.returncode != 0 or not result.stdout:
        return None
    for line in result.stdout.splitlines():
        m = re.match(r"\s+SSID:\s*(.+)", line)
        if m:
            ssid = m.group(1).strip()
            return ssid if ssid else None
    return None


def has_network_manager() -> bool:
    """Check if NetworkManager (nmcli) is installed."""
    return shutil.which("nmcli") is not None


def block_network_manager(iface: str) -> bool:
    """Tell NetworkManager to stop managing this interface during monitor mode.
    Returns True if action was taken (NM was running and command succeeded).
    """
    if not has_network_manager():
        return False
    result = _run(["nmcli", "dev", "set", iface, "managed", "no"])
    return result.returncode == 0


def unblock_network_manager(iface: str) -> bool:
    """Tell NetworkManager to resume managing this interface after monitor mode.
    Returns True if action was taken (NM was running and command succeeded).
    """
    if not has_network_manager():
        return False
    result = _run(["nmcli", "dev", "set", iface, "managed", "yes"])
    return result.returncode == 0


def enable_monitor_mode(iface: str) -> bool:
    """Switch interface to monitor mode via iw. Requires CAP_NET_ADMIN (root).
    Returns True on success, False on failure.
    """
    try:
        subprocess.run(
            ["ip", "link", "set", iface, "down"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["iw", "dev", iface, "set", "type", "monitor"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["ip", "link", "set", iface, "up"],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, OSError):
        # Best-effort: bring interface back up on failure
        try:
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        return False


def restore_managed_mode(iface: str) -> bool:
    """Restore interface to managed (station) mode via iw.
    Returns True on success, False on failure.
    """
    try:
        subprocess.run(
            ["ip", "link", "set", iface, "down"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["iw", "dev", iface, "set", "type", "managed"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["ip", "link", "set", iface, "up"],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, OSError):
        try:
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        return False


def reconnect_wifi(iface: str, ssid: str | None) -> bool:
    """Attempt to reconnect to a Wi-Fi network after restoring managed mode.
    Uses NetworkManager if available. Returns True if an IP address is
    obtained within the wait window.
    """
    if not has_network_manager():
        return False
    if ssid:
        _run(["nmcli", "dev", "wifi", "connect", ssid, "ifname", iface],
             timeout=30)
    else:
        _run(["nmcli", "dev", "connect", iface], timeout=10)
    time.sleep(3)
    result = _run(["ip", "-4", "addr", "show", iface])
    return "inet " in result.stdout


# ── Display helpers ──

BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"


def _terminal_width() -> int:
    """Get terminal width, defaulting to 72."""
    try:
        w = shutil.get_terminal_size().columns
        return max(60, min(w, 100))
    except Exception:
        return 72


def print_recommendation_banner(reason: str):
    """Print the ALFA-equipment recommendation banner."""
    width = _terminal_width()

    if reason == "no_adapter":
        title = f"{RED}\u26a0 NO WIRELESS HARDWARE FOUND{RESET}"
        body = [
            "PortShim requires a wireless adapter to perform RF",
            "scanning. No Wi-Fi interfaces were detected on this",
            "system.",
        ]
    else:
        title = f"{YELLOW}\u26a0 ALFA AWUS036ACH STRONGLY RECOMMENDED{RESET}"
        body = [
            "Internal laptop adapters lack monitor mode and packet",
            "injection. Without an external adapter you CANNOT:",
            "",
            "  \u2022 Capture WPA/WPA2 handshakes",
            "  \u2022 Deauthenticate clients",
            "  \u2022 Deploy evil twin access points",
            "  \u2022 Test WPA3 downgrade vulnerabilities",
            "  \u2022 Run passive Kismet monitoring",
        ]

    rec = [
        "",
        "Recommended: Alfa AWUS036ACH (Realtek RTL8812AU, ~$35)",
        "Supports monitor mode + injection on 2.4GHz and 5GHz.",
    ]

    # Calculate content width
    all_lines = body + rec
    content_width = max(len(line) for line in all_lines)
    content_width = max(content_width, len(re.sub(r'\033\[[0-9;]*m', '', title)))
    content_width = min(content_width, width - 4)

    # Build banner
    hr = "\u2550" * (content_width + 4)
    print(f"\n  \u2554{hr}\u2557")

    for t_line in title.split("\n"):
        stripped = re.sub(r'\033\[[0-9;]*m', '', t_line)
        pad = content_width - len(stripped)
        print(f"  \u2551  {t_line}{' ' * pad}  \u2551")

    print(f"  \u2551{' ' * (content_width + 4)}\u2551")

    for line in body:
        pad = content_width - len(line)
        print(f"  \u2551  {line}{' ' * pad}  \u2551")

    print(f"  \u2551{' ' * (content_width + 4)}\u2551")

    for line in rec:
        pad = content_width - len(line)
        print(f"  \u2551  {line}{' ' * pad}  \u2551")

    print(f"  \u255a{hr}\u255d")
    print()


def print_capability_table(adapters: list[dict], selected: str | None = None):
    """Print capability table for all detected adapters."""
    V = "\u2502"
    H = "\u2500"

    for adapter in adapters:
        name = adapter["name"]
        desc = adapter["description"]
        caps = adapter["capabilities"]

        sel = " \u2190 selected" if name == selected else ""
        print(f"  {BOLD}{name}{RESET} \u2014 {desc}{sel}")

        # Define rows
        rows = [
            ("Monitor mode", caps["monitor_mode"]),
            ("Packet injection", caps["packet_injection"]),
            ("2.4 GHz band", caps["band_2ghz"]),
            ("5 GHz band", caps["band_5ghz"]),
            ("6 GHz (Wi-Fi 6E)", caps["band_6ghz"]),
            ("External adapter", adapter.get("type") == "external"),
        ]

        # Column widths
        label_w = max(len(r[0]) for r in rows) + 1
        col_w = label_w + 4 + 3 + 1 + 8  # label | status

        print(f"    Capability{' ' * (label_w - 10)} Status")
        print(f"    {' ' + H * (col_w - 1)}")

        for label, ok in rows:
            tick = f"{GREEN}\u2713{RESET}" if ok else f"{RED}\u2717{RESET}"
            status_text = "supported" if ok else "unsupported"
            extra = ""
            if label == "External adapter" and ok:
                extra = f" {DIM}USB{RESET}"
            elif label == "External adapter" and not ok:
                extra = f" {DIM}internal only{RESET}"
            print(
                f"    {label:<{label_w}} {tick}  {status_text}{extra}"
            )

        # Scan mode
        mode = get_scan_mode(adapter)
        mode_labels = {
            "full": f"{GREEN}Full {DIM}(airodump-ng){RESET}",
            "passive": f"{YELLOW}Passive {DIM}(Kismet){RESET}",
            "managed": f"{YELLOW}Managed {DIM}(iw scan){RESET}",
        }
        print(f"\n    {BOLD}Scan mode:{RESET}  {mode_labels.get(mode, mode)}")
        if mode == "managed":
            print(f"    {DIM}Coverage: SSID list + BSSID + signal + encryption{RESET}")
            print(f"    {DIM}Missing:  no client enumeration, no hidden SSIDs,{RESET}")
            print(f"    {DIM}          no deauth, no handshake capture{RESET}")
        print()


# ── MAC spoofing ──

_MAC_SAVED = {}  # iface → original MAC address mapping


def get_current_mac(iface: str) -> str | None:
    """Get the current MAC address of an interface via ip link."""
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None

    for line in result.stdout.splitlines():
        stripped = line.strip()
        if "link/ether" in stripped:
            parts = stripped.split()
            for i, part in enumerate(parts):
                if part == "link/ether" and i + 1 < len(parts):
                    return parts[i + 1].lower()
    return None


def is_valid_mac(mac: str) -> bool:
    """Check if a MAC address is valid (not multicast, not broadcast, proper format)."""
    import re
    if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac):
        return False
    # Reject multicast (bit 0 of first octet set) and broadcast
    first_octet = int(mac.split(":")[0], 16)
    if first_octet & 0x01:  # multicast bit
        return False
    if mac.lower() == "ff:ff:ff:ff:ff:ff":  # broadcast
        return False
    return True


def random_mac() -> str:
    """Generate a random locally-administered unicast MAC address.

    Sets bit 1 (locally administered) and clears bit 0 (unicast) of the
    first octet, per IEEE 802 conventions.
    """
    import random
    octets = []
    # First octet: clear multicast bit (0x01), set locally-administered bit (0x02)
    first = random.randint(0, 255) & 0xFC | 0x02
    octets.append(first)
    for _ in range(5):
        octets.append(random.randint(0, 255))
    return ":".join(f"{o:02x}" for o in octets)


def spoof_mac(iface: str, new_mac: str) -> bool:
    """Change the MAC address of an interface.

    Tries macchanger first, falls back to ip link set.
    Returns True on success.
    """
    # Try macchanger first (handles driver quirks)
    try:
        subprocess.run(
            ["macchanger", "-m", new_mac, iface],
            capture_output=True, timeout=10, check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: ip link set
    try:
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "down"],
            capture_output=True, timeout=5, check=True,
        )
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "address", new_mac],
            capture_output=True, timeout=5, check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
    finally:
        # Always try to bring interface back up
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "up"],
            capture_output=True, timeout=5,
        )


def restore_mac(iface: str) -> bool:
    """Restore the permanent hardware MAC address via macchanger -p."""
    try:
        subprocess.run(
            ["macchanger", "-p", iface],
            capture_output=True, timeout=10, check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: not possible without macchanger (need permanent MAC)
    return False


def save_mac(iface: str, mac: str) -> None:
    """Save a MAC address for later restoration."""
    _MAC_SAVED[iface] = mac


def restore_saved_mac(iface: str) -> bool:
    """Restore a previously saved MAC address via ip link."""
    saved = _MAC_SAVED.pop(iface, None)
    if not saved:
        return False

    try:
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "down"],
            capture_output=True, timeout=5, check=True,
        )
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "address", saved],
            capture_output=True, timeout=5, check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
    finally:
        # Always bring interface back up
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "up"],
            capture_output=True, timeout=5,
        )

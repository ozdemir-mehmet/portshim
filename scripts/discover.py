#!/usr/bin/env python3
"""
PortShim Network Discovery — find all reachable VLANs/subnets from the current machine.

Usage:
    portshim discover                           # Standard (default, ~5 min)
    portshim discover --fast                    # Quick (~2 min)
    portshim discover --deep                    # Full (~10 min)
    portshim discover --interface eth0          # Explicit interface
    portshim discover --output network-map.json # Save to file

Outputs JSON to stdout (pipe-friendly) and human-readable table to stderr.
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from collections import OrderedDict
from pathlib import Path


# ── Colours (same palette as portshim) ──
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ── MAC OUI vendor database (commonly seen in office environments) ──
OUI_VENDORS = {
    "20:67:7C": "Hewlett Packard Enterprise",
    "00:04:A3": "Microchip Technology",
    "38:05:25": "Shenzhen Meigao",
    "48:A6:B8": "Sonos",
    "04:7C:16": "Micro-Star Intl (MSI)",
    "14:99:E2": "Apple",
    "80:6D:97": "Private",
    "00:1A:A0": "APC",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "HP Inc",
    "3C:D9:2B": "HP Inc",
    "98:F0:AB": "HP Inc",
    "F8:DB:88": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "00:26:86": "Hikvision",
    "EC:17:2F": "Cisco Systems",
    "F8:B7:E2": "Dell",
    "B8:AC:6F": "Dell",
    "34:64:A9": "Dell",
    "00:1E:4F": "Intel",
    "F0:1F:AF": "Intel",
    "B4:2E:99": "Intel",
    "00:17:C8": "MikroTik",
    "4C:5E:0C": "ASUSTek",
    "BC:AE:C5": "Samsung",
}

# ── Port-based classification heuristics ──
CLASSIFICATION_RULES = OrderedDict([
    # Ordered most specific → least specific
    ("switch", {
        "ports": {22, 80},
        "banners": ["eHTTP", "Mocana", "switch", "ProCurve", "ProVision"],
        "weight": 10,
    }),
    ("UPS", {
        "ports": {80, 443},
        "banners": ["APC", "UPS", "Network Management Card", "PowerChute", "apc"],
        "weight": 10,
        "require_banner": True,  # Port match alone isn't enough — too many devices serve HTTP
    }),
    ("Printer", {
        "ports": {80, 443, 515, 631},
        "banners": ["LaserJet", "printer", "Virata", "Printer"],
        "weight": 10,
    }),
    ("Camera", {
        "ports": {554, 80},
        "banners": ["RTSP", "GStreamer", "Hikvision", "Dahua", "camera"],
        "weight": 8,
        "require_banner": True,
    }),
    ("Signage", {
        "hostnames": ["signage", "sign", "display", "screen", "sign"],
        "weight": 9,
    }),
    ("KVM", {
        "banners": ["HDM-", "KVM", "iKVM", "Raritan"],
        "weight": 9,
    }),
    ("Windows Workstation", {
        "ports": {135, 445, 3389},
        "weight": 7,
    }),
    ("Windows Server", {
        "ports": {135, 445, 3389},
        "banners": ["IIS", "iis"],
        "hostnames": ["srv", "server", "dc", "sql", "exchange"],
        "weight": 9,
    }),
    ("Corporate LAN", {
        "ports": {135, 445, 3389},
        "hostnames": ["corp", "ssw", "local"],
        "weight": 6,
    }),
    ("UniFi Appliance", {
        "banners": ["#007cef", "unifi", "Ubiquiti"],
        "weight": 8,
    }),
    ("NAS", {
        "ports": {80, 443, 445, 548, 2049},
        "hostnames": ["nas", "storage", "synology", "qnap", "drobo"],
        "weight": 7,
        "require_banner": True,
    }),
    ("Linux Server", {
        "ports": {22},
        "banners": ["SSH", "Dropbear", "OpenSSH"],
        "weight": 4,
    }),
])


# ── Utility functions ──

def eprint(*args, **kwargs):
    """Print to stderr (for human-readable output; JSON goes to stdout)."""
    print(*args, file=sys.stderr, **kwargs)


def run_cmd(cmd, timeout=30, capture=True):
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=capture, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout.strip() if r.stdout else "", r.stderr.strip() if r.stderr else ""
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"


def run_nmap_sweep(cidr, use_tcp_syn=False):
    """
    Run nmap -sn on a subnet.
    If use_tcp_syn, adds TCP SYN ping probes for non-ICMP hosts.
    Returns (returncode, stdout) — caller parses the output.
    """
    # Try with sudo -n first (uses user's cached sudo credentials from interactive session)
    sudo_cmd = ["sudo", "-n", "nmap", "-sn", "-T4"]
    if use_tcp_syn:
        sudo_cmd.append("-PS22,80,443,3389,8080")
    sudo_cmd.append(cidr)
    sudo_code, sudo_out, sudo_err = run_cmd(sudo_cmd, timeout=30)
    
    if sudo_code == 0 and "Nmap done" in sudo_out:
        return sudo_code, sudo_out
    
    # Fallback: try without sudo (no MAC addresses, but hosts still found)
    cmd = ["nmap", "-sn", "-T4"]
    if use_tcp_syn:
        cmd.append("-PS22,80,443,3389,8080")
    cmd.append(cidr)
    code, out, _ = run_cmd(cmd, timeout=30)
    
    if code == 0 and "Nmap done" in out:
        return code, out
    
    # Return whatever we got (even if failed)
    return sudo_code, sudo_out


def get_current_interface_and_network():
    """Detect the active interface, IP, subnet, and gateway."""
    # Get interface info
    code, out, _ = run_cmd(["ip", "-4", "-o", "addr", "show"])
    if code != 0:
        return None, None, None, None

    # Find the default route interface
    gw_code, gw_out, _ = run_cmd(["ip", "-4", "route", "show", "default"])
    gateway = None
    if gw_code == 0 and gw_out:
        parts = gw_out.split()
        for i, p in enumerate(parts):
            if p == "via":
                gateway = parts[i + 1]
            elif p == "dev":
                default_iface = parts[i + 1]
    
    if not gateway:
        eprint(f"  {YELLOW}⚠ No default gateway found.{RESET}")
        return None, None, None, None

    # Find the interface matching the gateway's subnet
    local_ip = None
    subnet = None
    iface_name = None
    
    for line in out.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        for i, part in enumerate(parts):
            if "/" in part and i >= 3:
                try:
                    net = ipaddress.IPv4Network(part, strict=False)
                    # Check if gateway is in this subnet
                    gw_addr = ipaddress.IPv4Address(gateway)
                    if gw_addr in net:
                        iface_name = name
                        subnet = net
                        local_ip = part.split("/")[0]  # Extract actual IP from CIDR
                        break
                except ValueError:
                    pass
        if iface_name:
            break

    # Fallback: just use first non-loopback interface
    if not iface_name:
        for line in out.split("\n"):
            line = line.strip()
            if not line or "lo" in line:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[1]
            for part in parts:
                if "/" in part:
                    try:
                        net = ipaddress.IPv4Network(part, strict=False)
                        iface_name = name
                        subnet = net
                        # Get actual IP
                        for p in parts:
                            if "/" in p:
                                local_ip = p.split("/")[0]
                                break
                        break
                    except ValueError:
                        pass
            if iface_name:
                break

    return iface_name, local_ip, subnet, gateway


def get_oui_vendor(mac):
    """Look up MAC OUI vendor from the database."""
    if not mac:
        return None
    oui = mac.upper()[:8]
    return OUI_VENDORS.get(oui)


def detect_adjacent_subnets(gateway, local_subnet, proxy=10):
    """
    Probe nearby gateway IPs to find adjacent VLANs.
    Works by varying the likely subnet octet.
    
    For /24 networks: vary the third octet for 10.x.y.0/24, 
    fourth for 192.168.y.0/24.
    
    Returns list of (subnet_cidr, gateway_ip) tuples.
    """
    if not gateway or not local_subnet:
        return []
    
    try:
        gw = ipaddress.IPv4Address(gateway)
    except ValueError:
        return []
    
    octets = str(gw).split(".")
    discovered = [(str(local_subnet), gateway)]
    
    subnet_mask = local_subnet.prefixlen
    
    if subnet_mask == 24:
        # For /24, vary the octet just before the host portion
        if octets[0] == "10":
            # 10.x.y.0/24 — vary the third octet (index 2)
            base_octets = octets[:2]  # e.g. ["10", "100"]
            var_idx = 2
            fixed_octets = octets[:var_idx]
        elif octets[0] == "172" and 16 <= int(octets[1]) <= 31:
            # 172.16-31.y.0/24 — vary the third octet
            base_octets = octets[:2]
            var_idx = 2
            fixed_octets = octets[:var_idx]
        elif octets[0] == "192" and octets[1] == "168":
            # 192.168.y.0/24 — vary the third octet
            base_octets = octets[:2]
            var_idx = 2
            fixed_octets = octets[:var_idx]
        else:
            # Unknown /24 pattern, vary the third octet
            base_octets = octets[:2]
            var_idx = 2
            fixed_octets = octets[:var_idx]
    elif subnet_mask == 16:
        base_octets = octets[:1]
        var_idx = 1
        fixed_octets = octets[:var_idx]
    else:
        # Fallback: just probe a few IPs near the gateway
        for offset in range(-5, 6):
            if offset == 0:
                continue
            probe_octets = octets.copy()
            probe_octets[3] = str(int(octets[3]) + offset)
            probe_ip = ".".join(probe_octets)
            code, _, _ = run_cmd(["ping", "-c", "1", "-W", "1", probe_ip], timeout=2)
            if code == 0:
                cidr = f"{'.'.join(probe_octets[:3])}.0/24"
                discovered.append((cidr, probe_ip))
        return discovered
    
    # Probe common octet values for the variable octet
    # Probe a broad range but prioritise common VLAN numbers
    current_val = int(octets[var_idx])
    
    # Build probe list: nearby first, then common VLAN IDs
    probe_values = set()
    # Nearby ±10
    for offset in range(-10, 11):
        v = current_val + offset
        if 0 <= v <= 255 and v != current_val:
            probe_values.add(v)
    # Common VLANs
    for v in [20, 21, 30, 34, 35, 50, 100, 200, 254, 99, 10, 40, 60, 70, 80, 90]:
        if 0 <= v <= 255 and v != current_val:
            probe_values.add(v)
    
    for val in sorted(probe_values):
        probe_octets = octets.copy()
        probe_octets[var_idx] = str(val)
        probe_ip = ".".join(probe_octets)
        
        code, _, _ = run_cmd(["ping", "-c", "1", "-W", "1", probe_ip], timeout=2)
        if code == 0:
            cidr = f"{'.'.join(probe_octets[:3])}.0/24" if subnet_mask >= 24 else \
                   f"{'.'.join(probe_octets[:2])}.0.0/16" if subnet_mask >= 16 else \
                   f"{'.'.join(probe_octets[:1])}.0.0.0/8"
            if cidr not in [d[0] for d in discovered]:
                discovered.append((cidr, probe_ip))
                eprint(f"  {GREEN}✓{RESET} Found VLAN: {cidr} (gateway {probe_ip})")
    
    return discovered


def sweep_subnet(cidr, use_tcp_syn=False):
    """
    ICMP sweep a subnet. Returns list of {ip, mac, hostname} dicts.
    If use_tcp_syn, also run TCP SYN ping as fallback.
    """
    hosts = []
    code, out = run_nmap_sweep(cidr, use_tcp_syn)
    
    if code != 0 or not out:
        return hosts
    
    # Parse nmap output
    current_ip = None
    current_mac = None
    current_hostname = None
    
    for line in out.split("\n"):
        line = line.strip()
        
        m = re.match(r"Nmap scan report for (.+)", line)
        if m:
            if current_ip and current_ip != m.group(1):
                hosts.append({
                    "ip": current_ip,
                    "mac": current_mac,
                    "hostname": current_hostname,
                    "vendor": get_oui_vendor(current_mac),
                })
                current_mac = None
                current_hostname = None
            
            target = m.group(1)
            try:
                ipaddress.IPv4Address(target)
                current_ip = target
                current_hostname = None
            except ValueError:
                # Has a hostname
                parts = target.rsplit(" (", 1)
                if len(parts) == 2 and parts[1].endswith(")"):
                    current_hostname = parts[0]
                    current_ip = parts[1][:-1]
                else:
                    current_ip = target
                    current_hostname = None
        
        m = re.match(r"MAC Address: ([0-9A-Fa-f:]+)", line)
        if m:
            current_mac = m.group(1)
    
    if current_ip:
        hosts.append({
            "ip": current_ip,
            "mac": current_mac,
            "hostname": current_hostname,
            "vendor": get_oui_vendor(current_mac),
        })
    
    # TCP SYN fallback for non-ICMP hosts
    if use_tcp_syn:
        syn_code, syn_out = run_nmap_sweep(cidr, use_tcp_syn=True)
        
        if syn_code == 0:
            syn_ips = set()
            for line in syn_out.split("\n"):
                m = re.match(r"Nmap scan report for (.+)", line.strip())
                if m:
                    target = m.group(1)
                    try:
                        ipaddress.IPv4Address(target)
                        syn_ips.add(target)
                    except ValueError:
                        parts = target.rsplit(" (", 1)
                        if len(parts) == 2 and parts[1].endswith(")"):
                            syn_ips.add(parts[1][:-1])
                        else:
                            syn_ips.add(target)
            
            existing_ips = {h["ip"] for h in hosts}
            for ip in syn_ips - existing_ips:
                hosts.append({
                    "ip": ip,
                    "mac": None,
                    "hostname": None,
                    "vendor": None,
                })
    
    return hosts


def fingerprint_host(ip, depth="standard"):
    """
    Quick service scan on a host.
    Returns dict of open ports and service info.
    
    depth:
      'fast': top-20 ports, no version
      'standard': top-50 ports with version
      'deep': top-100 ports with version + HTTP title
    """
    info = {"ip": ip, "open_ports": [], "banners": [], "http_title": None}
    
    top_ports = {"fast": 20, "standard": 50, "deep": 100}[depth]
    
    cmd = ["nmap", "-T4", f"--top-ports={top_ports}", "-sV", "--open", ip]
    if depth == "deep":
        cmd.extend(["--script", "http-title"])
    
    code, out, _ = run_cmd(cmd, timeout=60 if depth == "deep" else 30)
    
    if code != 0:
        return info
    
    for line in out.split("\n"):
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)", line.strip())
        if m:
            port = int(m.group(1))
            service = m.group(3)
            extra = m.group(4).strip()
            info["open_ports"].append(port)
            if service and service != "unknown":
                info["banners"].append(service)
            if extra and extra != "?":
                # Extract version string
                version = extra.strip().rstrip("?")
                if version:
                    info["banners"].append(version)
    
    # HTTP title grab (if not done by nmap)
    if depth in ("standard", "deep") and info["open_ports"]:
        for port in info["open_ports"]:
            if port in (80, 443, 8080, 8443):
                proto = "https" if port in (443, 8443) else "http"
                title_code, title_out, _ = run_cmd(
                    ["curl", "-sk", "-m", "3", f"{proto}://{ip}:{port}"],
                    timeout=5,
                )
                if title_code == 0:
                    # Extract title
                    tm = re.search(r"<title>(.*?)</title>", title_out, re.IGNORECASE | re.DOTALL)
                    if tm:
                        title = tm.group(1).strip()[:80]
                        info["http_title"] = title
                        info["banners"].append(title)
                    elif title_out.strip():
                        # Check for known patterns in response
                        if "#007cef" in title_out:
                            info["banners"].append("UniFi UI")
                        elif "APC" in title_out or "UPS" in title_out:
                            info["banners"].append("APC UPS")
                        elif "HDM-" in title_out:
                            tm = re.search(r"HDM-\w+", title_out)
                            if tm:
                                info["banners"].append(tm.group(0))
                    break
    
    return info


def classify_subnet(hosts_info, subnet_cidr, depth="standard"):
    """
    Classify a subnet's purpose based on aggregated host evidence.
    Returns (purpose_label, evidence_list).
    """
    if not hosts_info:
        return "Empty", []
    
    # Gather all evidence
    all_banners = []
    all_hostnames = []
    all_vendors = []
    all_ports = set()
    http_titles = []
    
    for h in hosts_info:
        if h.get("vendor"):
            all_vendors.append(h["vendor"])
        if h.get("hostname"):
            all_hostnames.append(h["hostname"])
        if h.get("banners"):
            all_banners.extend(h["banners"])
        if h.get("open_ports"):
            all_ports.update(h["open_ports"])
        if h.get("http_title"):
            http_titles.append(h["http_title"])
        
        # Check fingerprint info if available
        fp = h.get("fingerprint", {})
        if fp.get("banners"):
            all_banners.extend(fp["banners"])
        if fp.get("open_ports"):
            all_ports.update(fp["open_ports"])
        if fp.get("http_title"):
            http_titles.append(fp["http_title"])
    
    evidence = []
    if all_vendors:
        evidence.append(f"{', '.join(sorted(set(all_vendors))[:3])}")
    if all_hostnames:
        evidence.append(f"hostnames: {', '.join(all_hostnames[:3])}")
    if all_ports:
        evidence.append(f"ports: {','.join(str(p) for p in sorted(all_ports)[:8])}")
    if http_titles:
        evidence.append(f"titles: {', '.join(http_titles[:3])}")
    
    # Score each classification
    scores = {}
    for label, rules in CLASSIFICATION_RULES.items():
        score = 0
        port_match = False
        banner_match = False
        
        # Check port matches
        if rules.get("ports") and rules["ports"].issubset(all_ports):
            port_match = True
            if not rules.get("require_banner"):
                score += rules.get("weight", 5)
        
        # Check banner matches
        if rules.get("banners"):
            for banner in rules["banners"]:
                for ab in all_banners:
                    if banner.lower() in ab.lower():
                        banner_match = True
                        score += rules.get("weight", 5)
                        break
                if banner_match:
                    break
        
        # Check hostname matches
        if rules.get("hostnames"):
            for hn in rules["hostnames"]:
                for h in all_hostnames:
                    if hn.lower() in h.lower():
                        score += rules.get("weight", 5)
                        break
        
        if score > 0:
            scores[label] = score
    
    # If only 1 host is the gateway, classify as "Unused"
    non_gateway_hosts = [h for h in hosts_info if h["ip"].endswith(".1")]
    host_count = len(hosts_info)
    non_gateway_count = host_count - 1  # subtract gateway
    
    if host_count <= 1:
        # Gateway only
        if all_banners:
            # Check if gateway has identifiable services
            if "ProCurve" in str(all_banners) or "ProVision" in str(all_banners) or "switch" in str(all_banners).lower():
                return "Infrastructure", evidence
            return "Unused", evidence
        return "Unused", []
    
    if scores:
        best = max(
            (k for k in scores if scores[k] is not None),
            key=lambda k: scores[k],
        )
        if scores[best] >= 7 or host_count >= 5:
            return best, evidence
    
    # Fallback heuristics
    if non_gateway_count >= 20:
        return "Corporate LAN", evidence
    if non_gateway_count >= 10:
        return "Corporate LAN", evidence
    if 135 in all_ports and 445 in all_ports and 3389 in all_ports:
        if 443 in all_ports or 8443 in all_ports:
            return "Server Room", evidence
        return "Corporate LAN", evidence
    if 22 in all_ports and 80 in all_ports and len(all_ports) <= 4:
        return "Infrastructure", evidence
    if 515 in all_ports or any("printer" in str(b).lower() for b in all_banners):
        return "Printing", evidence
    if any("APC" in str(b) for b in all_banners) or any("UPS" in str(b) for b in all_banners):
        return "Infrastructure", evidence
    
    if non_gateway_count <= 3:
        return "Sparse VLAN", evidence
    
    return "Unclassified", evidence


def run_discovery(depth="standard", interface=None, output_file=None):
    """
    Main discovery pipeline.
    """
    start_time = time.time()
    
    eprint(f"\n{BOLD}{CYAN}═══ PortShim Network Discovery ({depth} mode) ═══{RESET}\n")
    
    # Phase 0: Tool check
    eprint(f"{BOLD}Phase 0: Tool Check{RESET}")
    nmap_ok, _, _ = run_cmd(["nmap", "--version"], timeout=5)
    if nmap_ok == 0:
        eprint(f"  {GREEN}✓{RESET} nmap available")
    else:
        eprint(f"  {RED}✗ nmap not found. Install with: pacman -S nmap{RESET}")
        sys.exit(1)
    eprint()
    
    # Phase 1: Interface detection
    eprint(f"{BOLD}Phase 1: Interface Detection{RESET}")
    iface, local_ip, subnet, gateway = get_current_interface_and_network()
    
    if not iface or not local_ip or not subnet or not gateway:
        eprint(f"  {RED}✗ Could not determine network interface.{RESET}")
        eprint(f"  Use --interface to specify manually.")
        sys.exit(1)
    
    eprint(f"  {GREEN}✓{RESET} Interface: {iface}")
    eprint(f"  {GREEN}✓{RESET} Local IP:  {local_ip}")
    eprint(f"  {GREEN}✓{RESET} Subnet:    {subnet}")
    eprint(f"  {GREEN}✓{RESET} Gateway:   {gateway}")
    eprint()
    
    # Phase 2: Local subnet sweep
    eprint(f"{BOLD}Phase 2: Local Subnet Sweep{RESET}")
    eprint(f"  Scanning {subnet}... ", end="", flush=True)
    local_hosts = sweep_subnet(str(subnet))
    eprint(f"{GREEN}{len(local_hosts)} hosts{RESET}")
    for h in local_hosts:
        vendor = f" [{h['vendor']}]" if h['vendor'] else ""
        hostname = f" ({h['hostname']})" if h['hostname'] else ""
        eprint(f"    {h['ip']}{hostname}{vendor}")
    if depth == "standard" or depth == "deep":
        eprint(f"  Fingerprinting sample hosts...")
        sample_ips = [h["ip"] for h in local_hosts if not h["ip"].endswith(".1")][:5]
        for sip in sample_ips:
            fp = fingerprint_host(sip, depth)
            for h in local_hosts:
                if h["ip"] == sip:
                    h["fingerprint"] = fp
                    break
            ports = ",".join(str(p) for p in fp["open_ports"][:8])
            title = f" — {fp['http_title']}" if fp["http_title"] else ""
            eprint(f"    {sip}: [{ports}]{title}")
    eprint()
    
    # Phase 3: VLAN hunting
    eprint(f"{BOLD}Phase 3: VLAN Hunting{RESET}")
    eprint(f"  Probing gateway for adjacent subnets...")
    adjacent = detect_adjacent_subnets(gateway, subnet)
    eprint(f"  {GREEN}Found {len(adjacent)} reachable subnets{RESET}")
    eprint()
    
    # Phase 4: Sweep discovered VLANs
    eprint(f"{BOLD}Phase 4: Subnet Sweep{RESET}")
    subnet_data = {}
    
    for cidr, gw_ip in adjacent:
        subnet_data[cidr] = {
            "cidr": cidr,
            "gateway": gw_ip,
            "hosts": [],
            "host_count": 0,
        }
        
        if cidr == str(subnet):
            # Already scanned
            subnet_data[cidr]["hosts"] = local_hosts
            subnet_data[cidr]["host_count"] = len(local_hosts)
            continue
        
        if depth == "fast":
            eprint(f"  {cidr}: skipping (fast mode)")
            continue
        
        eprint(f"  Scanning {cidr}... ", end="", flush=True)
        hosts = sweep_subnet(cidr, use_tcp_syn=(depth == "deep"))
        subnet_data[cidr]["hosts"] = hosts
        subnet_data[cidr]["host_count"] = len(hosts)
        eprint(f"{GREEN}{len(hosts)} hosts{RESET}")
        
        for h in hosts[:5]:  # Show first 5
            vendor = f" [{h['vendor']}]" if h['vendor'] else ""
            hostname = f" ({h['hostname']})" if h['hostname'] else ""
            eprint(f"    {h['ip']}{hostname}{vendor}")
        if len(hosts) > 5:
            eprint(f"    ... and {len(hosts) - 5} more")
        
        # Fingerprint sample hosts
        if depth in ("standard", "deep") and hosts:
            sample_ips = [h["ip"] for h in hosts if not h["ip"].endswith(".1")][:3]
            for sip in sample_ips:
                fp = fingerprint_host(sip, depth)
                for h in hosts:
                    if h["ip"] == sip and "fingerprint" not in h:
                        h["fingerprint"] = fp
                        break
                ports = ",".join(str(p) for p in fp["open_ports"][:8])
                title = f" — {fp['http_title']}" if fp["http_title"] else ""
                if ports:
                    eprint(f"    {sip}: [{ports}]{title}")
    
    eprint()
    
    # Phase 5: Classification
    eprint(f"{BOLD}Phase 5: Classification{RESET}")
    results = []
    
    for cidr, data in sorted(subnet_data.items(), key=lambda x: ipaddress.IPv4Network(x[0], strict=False)):
        purpose, evidence = classify_subnet(
            data["hosts"], cidr, depth
        )
        data["purpose"] = purpose
        data["evidence"] = evidence
        
        host_count = data["host_count"]
        color = GREEN if host_count >= 5 else YELLOW if host_count >= 2 else ""
        eprint(f"  {color}{cidr:18}{RESET} {host_count:3} hosts  {BOLD}{purpose}{RESET}")
        if evidence:
            for ev in evidence[:2]:
                eprint(f"    {'':18} {ev}")
        
        results.append({
            "cidr": cidr,
            "gateway": data["gateway"],
            "host_count": host_count,
            "purpose": purpose,
            "evidence": evidence,
            "hosts": data["hosts"],
        })
    
    elapsed = time.time() - start_time
    total_hosts = sum(r["host_count"] for r in results)
    
    eprint(f"\n{BOLD}Summary:{RESET} {len(results)} subnets, {total_hosts} total hosts ({elapsed:.0f}s)")
    eprint()
    
    # Build output
    output = {
        "tool": "portshim discover",
        "version": "1.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "depth": depth,
        "duration_seconds": elapsed,
        "local_interface": iface,
        "local_ip": local_ip,
        "local_subnet": str(subnet),
        "gateway": gateway,
        "gateway_vendor": get_oui_vendor(None),
        "subnet_count": len(results),
        "total_hosts": total_hosts,
        "subnets": results,
    }
    
    # Gateway MAC vendor
    for h in local_hosts:
        if h["ip"] == gateway:
            output["gateway_vendor"] = h.get("vendor") or get_oui_vendor(h.get("mac")) or ""
            break
    
    json_output = json.dumps(output, indent=2, default=str)
    
    if output_file:
        Path(output_file).write_text(json_output)
        eprint(f"  {GREEN}✓{RESET} Saved to {output_file}")
    
    print(json_output)  # stdout = JSON only
    
    return output


def main():
    parser = argparse.ArgumentParser(
        description="PortShim Network Discovery — find all reachable VLANs/subnets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              portshim discover                   # Standard depth (default)
              portshim discover --fast            # Quick (~2 min)
              portshim discover --deep            # Full (~10 min)
              portshim discover --interface eth0  # Explicit interface
              portshim discover --output map.json # Save to file
        """),
    )
    
    parser.add_argument(
        "--fast", action="store_true",
        help="Quick discovery: local subnet + VLAN list only (~2 min)",
    )
    parser.add_argument(
        "--deep", action="store_true",
        help="Deep discovery: full sweep + TCP SYN fallback + all fingerprints (~10 min)",
    )
    parser.add_argument(
        "--interface", default=None,
        help="Network interface to use (auto-detect if not specified)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Save network map JSON to file (also printed to stdout)",
    )
    
    args = parser.parse_args()
    
    if args.fast and args.deep:
        eprint(f"{RED}Error: --fast and --deep are mutually exclusive.{RESET}")
        sys.exit(1)
    
    depth = "deep" if args.deep else ("fast" if args.fast else "standard")
    
    try:
        run_discovery(depth=depth, interface=args.interface, output_file=args.output)
    except KeyboardInterrupt:
        eprint(f"\n{YELLOW}Discovery interrupted.{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    # Need textwrap for epilog
    import textwrap
    main()

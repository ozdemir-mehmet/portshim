#!/usr/bin/env python3
"""
compare-nics.py — Benchmark wired Ethernet interfaces for PortShim suitability.

Runs identical nmap scans across every detected Ethernet interface and compares:
  - Host discovery count (ARP completeness)
  - Scan duration
  - Interface path (direct PCIe vs USB hub vs dock-bridged)

Usage:
  sudo .venv/bin/python scripts/diag/compare-nics.py                     # auto-detect subnet
  sudo .venv/bin/python scripts/diag/compare-nics.py --subnet 10.0.0.0/24
  sudo .venv/bin/python scripts/diag/compare-nics.py --subnet 192.168.1.0/24 --ports 22,80,443

Requires: nmap, root (for ARP + SYN scans)
"""

import subprocess, sys, os, json, time, re, argparse
from pathlib import Path

# ── Interface detection ────────────────────────────────────────────

SKIP_PATTERNS = ['lo', 'wlan', 'docker', 'veth', 'br-', 'virbr', 'tun', 'tap', 'wg', 'zt']


def get_ethernet_interfaces():
    """Return list of (ifname, driver, bus_path) for non-wireless, non-virtual NICs."""
    interfaces = []
    net_dir = Path('/sys/class/net')
    for iface_dir in sorted(net_dir.iterdir()):
        name = iface_dir.name
        if any(name.startswith(p) or name == p for p in SKIP_PATTERNS):
            continue

        # Check if wireless
        if (iface_dir / 'wireless').exists() or (iface_dir / 'phy80211').exists():
            continue

        # Get driver
        driver_link = iface_dir / 'device' / 'driver'
        driver = 'unknown'
        if driver_link.exists():
            driver = driver_link.resolve().name

        # Get bus topology
        device_link = iface_dir / 'device'
        bus_path = 'unknown'
        if device_link.exists():
            resolved = str(device_link.resolve())
            # Extract USB path if applicable
            usb_match = re.search(r'(usb\d+/[\d\-.]+)', resolved)
            pci_match = re.search(r'(0000:[\da-f:.]+)', resolved)
            if usb_match:
                bus_path = f'USB:{usb_match.group(1)}'
            elif pci_match:
                bus_path = f'PCI:{pci_match.group(1)}'

        # Get link state
        operstate = (iface_dir / 'operstate').read_text().strip() if (iface_dir / 'operstate').exists() else 'unknown'

        interfaces.append({
            'name': name,
            'driver': driver,
            'bus': bus_path,
            'state': operstate,
        })
    return interfaces


def detect_subnet(ifname):
    """Auto-detect the subnet for an interface via 'ip addr'."""
    result = subprocess.run(
        ['ip', '-4', '-o', 'addr', 'show', ifname],
        capture_output=True, text=True, timeout=5
    )
    for line in result.stdout.splitlines():
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
        if m:
            ip = m.group(1)
            prefix = int(m.group(2))
            # Calculate network address
            ip_parts = [int(x) for x in ip.split('.')]
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            net_parts = [str((ip_parts[0] << 24 | ip_parts[1] << 16 | ip_parts[2] << 8 | ip_parts[3]) & mask >> shift & 0xFF) 
                         if False else None]
            # Simpler: use ipcalc or just construct directly
            net_int = (ip_parts[0] << 24 | ip_parts[1] << 16 | ip_parts[2] << 8 | ip_parts[3]) & mask
            net_ip = f'{(net_int >> 24) & 0xFF}.{(net_int >> 16) & 0xFF}.{(net_int >> 8) & 0xFF}.{net_int & 0xFF}'
            return f'{net_ip}/{prefix}'
    return None


def get_interface_speed(ifname):
    """Get link speed from ethtool."""
    try:
        result = subprocess.run(
            ['ethtool', ifname],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r'Speed: (\S+)', result.stdout)
        return m.group(1) if m else 'unknown'
    except Exception:
        return 'unknown'


# ── nmap scans ─────────────────────────────────────────────────────

def run_host_discovery(ifname, subnet):
    """ARP ping scan — measure host count and scan time."""
    start = time.time()
    result = subprocess.run(
        ['nmap', '-sn', '-e', ifname, '--send-eth', subnet,
         '-oX', '-', '--max-retries', '2', '--max-rtt-timeout', '500ms'],
        capture_output=True, text=True, timeout=120
    )
    duration = time.time() - start

    hosts = len(re.findall(r'<host>.*?<status state="up"', result.stdout, re.DOTALL))
    return {
        'hosts_up': hosts,
        'duration_s': round(duration, 1),
        'exit_code': result.returncode,
        'stderr': result.stderr.strip()[:200] if result.stderr else '',
    }


def run_port_scan(ifname, subnet, ports='22,80,443,3389,8080,8443'):
    """SYN scan of common ports on discovered hosts."""
    start = time.time()
    result = subprocess.run(
        ['nmap', '-sS', '-e', ifname, '-p', ports,
         '--open', subnet,
         '-oX', '-', '--max-retries', '1', '--max-rtt-timeout', '300ms',
         '--min-rate', '500'],
        capture_output=True, text=True, timeout=180
    )
    duration = time.time() - start

    open_ports = len(re.findall(r'<port .*?><state state="open"', result.stdout, re.DOTALL))
    hosts_scanned = len(re.findall(r'<host ', result.stdout))
    return {
        'open_ports': open_ports,
        'hosts_scanned': hosts_scanned,
        'duration_s': round(duration, 1),
        'exit_code': result.returncode,
    }


# ── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Compare Ethernet NIC performance for PortShim')
    parser.add_argument('--subnet', help='Target subnet (auto-detected if omitted)')
    parser.add_argument('--ports', default='22,80,443,3389,8080,8443', help='Ports for SYN scan')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root for ARP + SYN scans (sudo)")
        sys.exit(1)

    if not Path('/usr/bin/nmap').exists():
        print("ERROR: nmap not found — install with: sudo pacman -S nmap")
        sys.exit(1)

    ifaces = get_ethernet_interfaces()
    if not ifaces:
        print("No Ethernet interfaces detected. Connect an adapter and try again.")
        sys.exit(1)

    print(f"=== Found {len(ifaces)} Ethernet interface(s) ===\n")
    for nic in ifaces:
        speed = get_interface_speed(nic['name']) if nic['state'] == 'up' else 'down'
        print(f"  {nic['name']:20s} driver={nic['driver']:12s} state={nic['state']:8s} "
              f"speed={speed:10s} bus={nic['bus']}")

    print()

    # Determine subnet
    subnet = args.subnet
    if not subnet:
        for nic in ifaces:
            if nic['state'] == 'up':
                subnet = detect_subnet(nic['name'])
                if subnet:
                    print(f"Auto-detected subnet: {subnet} (from {nic['name']})")
                    break
        if not subnet:
            print("ERROR: No subnet found. Plug in a cable or pass --subnet manually.")
            sys.exit(1)

    print(f"\nTarget: {subnet}")
    print(f"Ports:  {args.ports}\n")

    # Run scans
    results = []
    for nic in ifaces:
        print(f"{'─' * 60}")
        print(f"Testing {nic['name']} (driver={nic['driver']}, bus={nic['bus']})")

        if nic['state'] != 'up':
            # Try to bring it up
            subprocess.run(['ip', 'link', 'set', nic['name'], 'up'], capture_output=True, timeout=5)
            time.sleep(1)
            # Re-check
            operstate = (Path('/sys/class/net') / nic['name'] / 'operstate').read_text().strip()
            if operstate != 'up':
                print(f"  SKIP: interface is DOWN (no cable?)")
                results.append({**nic, 'status': 'DOWN', 'discovery': None, 'ports': None})
                continue

        nic['state'] = 'up'
        print(f"  ARP host discovery...")
        discovery = run_host_discovery(nic['name'], subnet)
        print(f"    → {discovery['hosts_up']} hosts up in {discovery['duration_s']}s")

        if discovery['hosts_up'] == 0:
            print(f"  SYN scan SKIPPED (no hosts found)")
            results.append({**nic, 'status': 'OK', 'discovery': discovery, 'ports': None})
            continue

        print(f"  SYN port scan...")
        ports = run_port_scan(nic['name'], subnet, args.ports)
        print(f"    → {ports['open_ports']} open ports on {ports['hosts_scanned']} hosts "
              f"in {ports['duration_s']}s")

        results.append({**nic, 'status': 'OK', 'discovery': discovery, 'ports': ports})

    # ── Summary ──────────────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print(f"{'SUMMARY':^70}")
    print(f"{'═' * 70}")

    # Table header
    print(f"\n{'Interface':<18} {'Bus Type':<14} {'Driver':<12} {'Discovery':>12} {'Hosts':>7} {'Port Scan':>12} {'Open Ports':>10}")
    print(f"{'─' * 18} {'─' * 14} {'─' * 12} {'─' * 12} {'─' * 7} {'─' * 12} {'─' * 10}")

    best_discovery = None
    best_iface = None

    for r in results:
        bus_type = 'PCIe (native)' if r['bus'].startswith('PCI:') else 'USB (adapter)' if r['bus'].startswith('USB:') else r['bus'][:14]
        disc_str = f"{r['discovery']['duration_s']}s" if r.get('discovery') else '—'
        hosts_str = str(r['discovery']['hosts_up']) if r.get('discovery') else '—'
        port_str = f"{r['ports']['duration_s']}s" if r.get('ports') else '—'
        open_str = str(r['ports']['open_ports']) if r.get('ports') else '—'

        print(f"{r['name']:<18} {bus_type:<14} {r['driver']:<12} {disc_str:>12} {hosts_str:>7} {port_str:>12} {open_str:>10}")

        if r.get('discovery') and r['discovery']['hosts_up'] > 0:
            if best_discovery is None or r['discovery']['hosts_up'] > best_discovery['hosts_up']:
                best_discovery = r['discovery']
                best_iface = r['name']

    print()

    # Winner
    if best_iface and len([r for r in results if r.get('discovery') and r['discovery']['hosts_up'] > 0]) > 1:
        print("Verdict: Use the interface that finds the MOST hosts and has the FASTEST discovery.")
        print(f"         If counts are equal, prefer PCIe > direct USB > dock-bridged USB.\n")

    # Bus path analysis
    print("Bus path analysis:")
    for r in results:
        if r['bus'].startswith('USB:'):
            path = r['bus'].split(':', 1)[1]
            hub_count = path.count('.') + path.count('-')
            if hub_count > 2:
                print(f"  ⚠ {r['name']}: traverses {hub_count} USB hubs — consider a direct adapter")
            else:
                print(f"  ✓ {r['name']}: short USB path ({hub_count} hops) — should be fine")
        elif r['bus'].startswith('PCI:'):
            print(f"  ✓ {r['name']}: direct PCIe — optimal for scanning")

    if args.json:
        print(f"\n{json.dumps(results, indent=2)}")


if __name__ == '__main__':
    main()

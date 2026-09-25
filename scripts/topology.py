#!/usr/bin/env python3
"""
topology.py — Parse nmap XML output into structured host tables and diagrams.

Takes nmap XML scan results and produces:
  - Terminal-readable host table
  - JSON for downstream tools (report generator)
  - Optional graphviz DOT for network diagram

Usage:
    python topology.py scan.xml                     # Print table
    python topology.py scan.xml --json              # JSON output
    python topology.py scan.xml --dot               # Graphviz DOT output
    python topology.py scan.xml --enrich cves.json  # Annotate with CVE data
    python topology.py scan.xml --httpx httpx.json  # Merge HTTP titles
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse nmap XML into structured host list."""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"Error parsing nmap XML: {e}", file=sys.stderr)
        return []
    root = tree.getroot()

    hosts = []
    for host_elem in root.findall("host"):
        host = {
            "ip": None,
            "hostname": None,
            "mac": None,
            "mac_vendor": None,
            "os": None,
            "status": "unknown",
            "ports": [],
            "cves": [],
        }

        # Status
        status_elem = host_elem.find("status")
        if status_elem is not None:
            host["status"] = status_elem.get("state", "unknown")

        # Addresses
        for addr in host_elem.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                host["ip"] = addr.get("addr")
            elif addr_type == "mac":
                host["mac"] = addr.get("addr")
                host["mac_vendor"] = addr.get("vendor")

        # Hostnames
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            for hname in hostnames.findall("hostname"):
                if hname.get("type") == "PTR":
                    host["hostname"] = hname.get("name")
                    break
                elif host["hostname"] is None:
                    host["hostname"] = hname.get("name")

        # OS detection
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for match in os_elem.findall("osmatch"):
                host["os"] = match.get("name")
                break

        # Ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_info = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": None,
                    "service": None,
                    "product": None,
                    "version": None,
                    "title": "",
                }
                state_elem = port.find("state")
                if state_elem is not None:
                    port_info["state"] = state_elem.get("state")

                service_elem = port.find("service")
                if service_elem is not None:
                    port_info["service"] = service_elem.get("name")
                    port_info["product"] = service_elem.get("product")
                    port_info["version"] = service_elem.get("version")

                if port_info["state"] == "open":
                    host["ports"].append(port_info)

        if host["ip"]:
            hosts.append(host)

    return sorted(hosts, key=lambda h: _ip_sort_key(h["ip"]))


def merge_httpx_titles(hosts: list[dict], httpx_json_path: str) -> list[dict]:
    """Merge HTTP titles from httpx JSON output into host port objects."""
    with open(httpx_json_path) as f:
        httpx_results = json.load(f)

    # Build lookup: ip:port -> title
    title_map = {}
    for entry in httpx_results:
        ip = entry.get("host") or entry.get("ip", "")
        port = str(entry.get("port", "80"))
        title = entry.get("title") or entry.get("webserver", "")
        if ip and title:
            title_map[f"{ip}:{port}"] = title

    for host in hosts:
        for port in host.get("ports", []):
            key = f"{host['ip']}:{port['port']}"
            if key in title_map:
                port["title"] = title_map[key]

    return hosts


def _ip_sort_key(ip: str) -> tuple:
    """Sort IP addresses numerically."""
    try:
        return tuple(int(octet) for octet in ip.split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


def enrich_with_cves(hosts: list[dict], cve_data: list[dict]) -> list[dict]:
    """Annotate hosts with CVE data from nmap-vulners or manual input."""
    cve_map = {}
    for entry in cve_data:
        key = f"{entry.get('ip')}:{entry.get('port')}"
        cve_map[key] = entry.get("cves", [])

    for host in hosts:
        for port in host.get("ports", []):
            key = f"{host['ip']}:{port['port']}"
            if key in cve_map:
                host["cves"].extend(cve_map[key])
                port["cves"] = cve_map[key]

    return hosts


def render_table(hosts: list[dict]) -> str:
    """Pretty-print as terminal table."""
    lines = []
    lines.append(f"Network Topology — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"{'IP':<16} {'Hostname':<30} {'OS':<25} {'Open Ports'}")
    lines.append("-" * 120)

    for host in hosts:
        ip = host["ip"] or "?"
        hostname = (host["hostname"] or "")[:29]
        os_info = (host["os"] or "")[:24]

        ports_str = []
        for port in host["ports"]:
            svc = port.get("service", "?")
            product = port.get("product", "")
            version = port.get("version", "")
            title = port.get("title", "")
            detail = f"{port['port']}/{port['protocol']}({svc}"
            if product:
                detail += f":{product}"
                if version:
                    detail += f" {version}"
            detail += ")"
            if port.get("cves"):
                detail += f" [{len(port['cves'])} CVE]"
            if title:
                detail += f' "{title[:30]}"'
            ports_str.append(detail)

        lines.append(f"{ip:<16} {hostname:<30} {os_info:<25} {', '.join(ports_str) if ports_str else 'none'}")

        # CVE summary per host
        if host.get("cves"):
            cve_ids = [c.get("id", "?") for c in host["cves"]]
            lines.append(f"  CVEs: {', '.join(cve_ids[:5])}{'...' if len(cve_ids) > 5 else ''}")

    lines.append("-" * 120)
    lines.append(f"Total hosts: {len(hosts)}  |  Total open ports: {sum(len(h['ports']) for h in hosts)}")
    return "\n".join(lines)


def render_json(hosts: list[dict]) -> str:
    """Output structured JSON."""
    return json.dumps({
        "scan_date": datetime.now().isoformat(),
        "host_count": len(hosts),
        "hosts": hosts,
    }, indent=2)


def render_dot(hosts: list[dict]) -> str:
    """Generate graphviz DOT for network topology diagram."""
    lines = ["digraph NetworkTopology {",
             "  rankdir=LR;",
             "  node [shape=box, style=filled, fillcolor=white, fontname=Helvetica];",
             "  edge [color=\"#CC4141\", fontname=Helvetica, fontsize=9];",
             ""]

    lines.append("  subgraph cluster_legend {")
    lines.append('    label="Legend";')
    lines.append("    style=filled;")
    lines.append("    fillcolor=\"#F5F5F5\";")
    lines.append("    legend_critical [label=\"Critical CVEs\", fillcolor=\"#CC4141\", fontcolor=white];")
    lines.append("    legend_high [label=\"High CVEs\", fillcolor=\"#FF8C00\", fontcolor=white];")
    lines.append("    legend_clean [label=\"No CVEs\", fillcolor=\"#90EE90\"];")
    lines.append("  }")
    lines.append("")

    for host in hosts:
        node_id = host["ip"].replace(".", "_")
        label = f"{host['ip']}\\n{(host.get('hostname') or '')[:20]}"

        cve_severity = "none"
        for cve in host.get("cves", []):
            if cve.get("severity") == "critical":
                cve_severity = "critical"
                break
            if cve.get("severity") == "high":
                cve_severity = "high"

        color_map = {"critical": "#CC4141", "high": "#FF8C00", "none": "#90EE90"}
        font_color = "white" if cve_severity in ("critical", "high") else "black"

        lines.append(f'  {node_id} [label="{label}", fillcolor="{color_map[cve_severity]}", fontcolor="{font_color}"];')

    lines.append("}")
    return "\n".join(lines)


def render_gate1(hosts: list[dict]) -> str:
    """Compact Gate 1 review summary — complete host list, never truncated.
    
    Groups hosts into risk categories and shows one line per host.
    Designed to be the single source of truth for operator review gates.
    """
    lines = []
    lines.append("=" * 80)
    lines.append("  GATE 1 — NETWORK RECONNAISSANCE SUMMARY")
    lines.append(f"  Generated from nmap XML: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)

    # Categorise hosts
    high_risk = []
    medium_risk = []
    low_risk = []
    no_ports = []

    for host in hosts:
        ip = host["ip"] or "?"
        hostname = host.get("hostname") or ""
        ports = host.get("ports", [])
        os_info = host.get("os") or ""
        cve_count = len(host.get("cves", []))

        # Determine risk level
        risk = "low"
        for p in ports:
            svc = p.get("service", "")
            product = p.get("product", "") or ""
            version = p.get("version", "") or ""
            port_str = f"{p['port']}/{p['protocol']}({svc})"

            # High risk flags
            if svc in ("telnet", "ms-wbt-server", "vnc") and p.get("state") == "open":
                risk = "high"
            if svc == "ssh" and "7" in version.split(".")[0] if version else False:
                risk = "high"
            if cve_count > 0:
                risk = "high" if risk != "high" else risk
            if svc in ("upnp", "snmp") and p.get("state") == "open":
                risk = "medium" if risk != "high" else risk
            if svc == "http" and p.get("state") == "open":
                risk = "medium" if risk == "low" else risk

        entry = {
            "ip": ip,
            "hostname": hostname[:28] if hostname else "-",
            "os": os_info[:20] if os_info else "-",
            "ports": ", ".join(
                f"{p['port']}/{p['protocol']}({p.get('service','?')})"
                for p in ports
            ) if ports else "none",
            "cves": cve_count,
            "risk": risk,
        }

        if not ports:
            no_ports.append(entry)
        elif risk == "high":
            high_risk.append(entry)
        elif risk == "medium":
            medium_risk.append(entry)
        else:
            low_risk.append(entry)

    def _print_group(group, label, icon):
        if not group:
            return
        lines.append(f"\n  {icon} {label} ({len(group)} hosts)")
        lines.append(f"  {'IP':<16} {'Hostname':<30} {'OS':<22} {'Open Ports'}")
        lines.append(f"  {'--':<16} {'--':<30} {'--':<22} {'--'}")
        for e in group:
            lines.append(f"  {e['ip']:<16} {e['hostname']:<30} {e['os']:<22} {e['ports']}")
            if e['cves'] > 0:
                lines.append(f"  {'':>16} {'':>30} {'':>22} CVEs flagged: {e['cves']}")
        lines.append("")

    _print_group(high_risk, "HIGH RISK", "!!!")
    _print_group(medium_risk, "MEDIUM RISK", "-->")
    _print_group(low_risk, "LOW RISK", "   ")
    
    if no_ports:
        lines.append(f"  [ ] No open ports ({len(no_ports)} hosts)")
        for e in no_ports:
            hostname_str = f" ({e['hostname']})" if e['hostname'] != "-" else ""
            lines.append(f"      {e['ip']}{hostname_str}")

    lines.append("=" * 80)
    lines.append(f"  Total: {len(hosts)} hosts  |  High risk: {len(high_risk)}  |  Medium: {len(medium_risk)}  |  Low: {len(low_risk)}  |  No ports: {len(no_ports)}")
    lines.append("=" * 80)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Parse nmap XML to topology table")
    parser.add_argument("xml", nargs="?", help="nmap XML output file (omit for stdin)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--dot", action="store_true", help="Output as graphviz DOT")
    parser.add_argument("--gate1", action="store_true", help="Compact Gate 1 review summary — never truncated")
    parser.add_argument("--enrich", type=str, help="JSON file with CVE annotations")
    parser.add_argument("--httpx", type=str, help="httpx JSON output for HTTP title enrichment")
    args = parser.parse_args()

    if args.xml:
        hosts = parse_nmap_xml(args.xml)
    else:
        hosts = parse_nmap_xml(sys.stdin)

    if args.httpx:
        hosts = merge_httpx_titles(hosts, args.httpx)

    if args.enrich:
        with open(args.enrich) as f:
            cve_data = json.load(f)
        hosts = enrich_with_cves(hosts, cve_data)

    if args.gate1:
        print(render_gate1(hosts))
    elif args.json:
        print(render_json(hosts))
    elif args.dot:
        print(render_dot(hosts))
    else:
        print(render_table(hosts))


if __name__ == "__main__":
    main()

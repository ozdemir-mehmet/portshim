#!/usr/bin/env python3
"""
generate-findings.py — Convert nmap vulners output to findings.json with NVD verification.

Reads phase1-nmap.xml, extracts CVEs from vulners NSE script output, cross-references
every CVE against the NVD API, re-classifies severity based on actual attack vector
and affected component, sanitizes version strings, and writes findings.json.

Usage:
    python scripts/generate-findings.py outputs/phase1-nmap.xml --output outputs/findings.json
    python scripts/generate-findings.py outputs/phase1-nmap.xml --output findings.json --no-nvd

Environment:
    NVD_API_KEY    NVD API key for higher rate limits (50 req/30s vs 5 req/30s)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE = {}  # In-memory cache to avoid re-querying the same CVE
RATE_LIMIT_SLEEP = 6  # Seconds between NVD API calls (unauthenticated: 5 req/30s)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unverified": 5}


def load_nvd_api_key() -> str | None:
    """Get NVD API key from environment."""
    return os.environ.get("NVD_API_KEY")


def sanitize_version(version: str) -> str:
    """Strip distro package suffixes from version strings.

    'OpenSSH 10.2p1 Ubuntu 2ubuntu3.2' → 'OpenSSH 10.2p1'
    'nginx 1.18.0-2+deb11u3'         → 'nginx 1.18.0'
    """
    if not version:
        return version

    # Common distro suffix patterns
    patterns = [
        r"\s+Ubuntu\s+\d+ubuntu[\d.]+.*$",
        r"\s+Debian\s+\d+\+deb\d+u\d+.*$",
        r"\s+Debian\s+[\d.]+$",
        r"-[\d]+ubuntu[\d.]+.*$",
        r"-[\d]+\+deb\d+u\d+.*$",
        r"\s+\(Ubuntu.*\)$",
    ]
    for pat in patterns:
        version = re.sub(pat, "", version).strip()
    return version


def query_nvd(cve_id: str, api_key: str | None = None) -> dict | None:
    """Query NVD API for a CVE. Returns parsed data or None."""
    if cve_id in NVD_CACHE:
        return NVD_CACHE[cve_id]

    url = f"{NVD_API}?cveId={cve_id}"
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, OSError):
        NVD_CACHE[cve_id] = None
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        NVD_CACHE[cve_id] = None
        return None

    cve_data = vulnerabilities[0].get("cve", {})
    NVD_CACHE[cve_id] = cve_data

    # Rate limit sleep
    if not api_key:
        time.sleep(RATE_LIMIT_SLEEP)
    return cve_data


def parse_cvss_from_nvd(cve_data: dict) -> tuple[float | None, str, str]:
    """Extract CVSS score, vector, and attack vector from NVD CVE data."""
    metrics = cve_data.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_v30 = metrics.get("cvssMetricV30", [])

    for metrics_list in [cvss_v31, cvss_v30]:
        for entry in metrics_list:
            cvss = entry.get("cvssData", {})
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString", "")
            attack_vector = cvss.get("attackVector", "")
            if score is not None:
                return score, vector, attack_vector

    return None, "", ""


def is_client_side(cve_data: dict) -> bool:
    """Check if a CVE requires user interaction (client-side)."""
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            text = desc.get("value", "").lower()
            if any(phrase in text for phrase in [
                "user interaction", "user-assisted", "requires a user",
                "convince a user", "trick a user", "social engineering",
                "drive-by", "phishing", "client-side", "client side"
            ]):
                return True

    metrics = cve_data.get("metrics", {})
    for metrics_list in [metrics.get("cvssMetricV31", []), metrics.get("cvssMetricV30", [])]:
        for entry in metrics_list:
            cvss = entry.get("cvssData", {})
            if cvss.get("userInteraction") == "REQUIRED":
                return True

    return False


def classify_severity(cvss_score: float | None, cve_data: dict | None,
                      is_server_target: bool) -> str:
    """Determine severity based on NVD data and target context."""
    if cve_data is None:
        # No NVD data — fall back to available CVSS score
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return "critical"
            if cvss_score >= 7.0:
                return "high"
            if cvss_score >= 4.0:
                return "medium"
            return "low"
        return "unverified"

    # Client-side CVE on a server → never critical/high
    if is_server_target and is_client_side(cve_data):
        if cvss_score is not None and cvss_score >= 9.0:
            return "medium"  # Downgrade: can't be exploited remotely
        return "low"

    # Use NVD CVSS score
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        return "low"

    # No CVSS available
    return "info"


def extract_vulners_cves(port_elem: ET.Element) -> list[dict]:
    """Extract CVE entries from a vulners script element in nmap XML."""
    cves = []
    for script in port_elem.findall("script"):
        if script.get("id") != "vulners":
            continue
        output = script.get("output", "")
        for line in output.split("\n"):
            m = re.match(r'\s+(CVE-\d{4}-\d{4,})\s+([\d.]+)', line)
            if m:
                cves.append({
                    "id": m.group(1),
                    "cvss_nmap": float(m.group(2)),
                })
    return cves


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse nmap XML into structured host/port/CVE data."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host_elem in root.findall("host"):
        ip = None
        hostname = None
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")

        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                hostname = hn.get("name", "")
                break

        if not ip:
            continue

        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_id = port_elem.get("portid")
            if not port_id:
                continue
            service_elem = port_elem.find("service")
            service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""

            cves = extract_vulners_cves(port_elem)

            hosts.append({
                "ip": ip,
                "hostname": hostname or "",
                "port": int(port_id),
                "service": service,
                "product": product,
                "version": sanitize_version(version),
                "version_raw": version,
                "cves": cves,
            })

    return hosts


def generate_findings(hosts: list[dict], use_nvd: bool = True,
                      api_key: str | None = None,
                      device_data: dict[str, dict] | None = None) -> list[dict]:
    """Generate findings.json entries with NVD verification and optional device classification."""
    findings = []
    finding_id = 1
    device_data = device_data or {}

    for host in hosts:
        ip = host["ip"]
        hostname = host["hostname"]
        port = host["port"]
        service = host["service"]
        product = host["product"]
        version = host["version"]

        # Device classification for this IP
        dev_info = device_data.get(ip, {})
        device_type = dev_info.get("device_type", "")
        device_vendor = dev_info.get("device_vendor", "")

        # Determine if this is a server target (not a client/endpoint)
        # SSH, HTTP servers, databases, etc. are server targets
        server_services = {"ssh", "http", "https", "mysql", "postgresql", "mssql",
                          "redis", "mongodb", "ftp", "smtp", "imap", "pop3",
                          "rpcbind", "ldap", "snmp", "telnet", "rdp", "smb"}
        is_server = service in server_services or port in (22, 23, 80, 111, 161, 443, 3306, 5432, 1433, 6379, 27017, 21, 25, 143, 110, 389, 3389, 445)

        if host["cves"]:
            # Consolidate all CVEs into one finding per host:port
            cve_list = sorted(host["cves"], key=lambda c: -c["cvss_nmap"])
            top_cve = cve_list[0]
            cve_count = len(cve_list)

            # Verify top CVE against NVD
            cvss_nvd = None
            cvss_vector = ""
            cve_data = None
            if use_nvd:
                cve_data = query_nvd(top_cve["id"], api_key)
                if cve_data:
                    cvss_nvd, cvss_vector, _ = parse_cvss_from_nvd(cve_data)

            cvss_final = cvss_nvd if cvss_nvd is not None else top_cve["cvss_nmap"]
            severity = classify_severity(cvss_final, cve_data, is_server)

            # Build CVE summary
            top_cves_str = ", ".join(
                f"{c['id']} ({c['cvss_nmap']})" for c in cve_list[:5]
            )
            if cve_count > 5:
                top_cves_str += f", +{cve_count - 5} more"

            desc_suffix = f"has {cve_count} known CVE{'s' if cve_count != 1 else ''}. Top: {top_cves_str}."
            description = (
                f"Host {ip}:{port} ({product} {version or 'unknown version'}) {desc_suffix}"
            )

            title = f"{product} {version} — {cve_count} CVEs (top: {top_cve['id']} {cvss_final})"

            # Check searchsploit for exploits
            exploits = lookup_exploit(top_cve["id"])
            exploit_available = len(exploits) > 0
            exploit_paths = [e["path"] for e in exploits]

            findings.append({
                "id": f"FIND-{finding_id:03d}",
                "title": title,
                "host": ip,
                "hostname": hostname,
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "cve": top_cve["id"],
                "cvss_score": cvss_final,
                "cvss_vector": cvss_vector,
                "severity": severity,
                "description": description,
                "remediation": f"Upgrade {product} to a patched version addressing these CVEs.",
                "status": "open",
                "device_type": device_type,
                "device_vendor": device_vendor,
                "cve_count": cve_count,
                "cve_list": [c["id"] for c in cve_list],
                "exploit_available": exploit_available,
                "exploit_paths": exploit_paths,
                "exploit_count": len(exploits),
            })
            finding_id += 1
        else:
            # Service without CVEs — note informational
            if service in ("http", "https", "unknown"):
                findings.append({
                    "id": f"FIND-{finding_id:03d}",
                    "title": f"Open {service} port on {product or 'unknown service'}",
                    "host": ip,
                    "hostname": hostname,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "cve": "",
                    "cvss_score": None,
                    "cvss_vector": "",
                    "severity": "info",
                    "description": (
                        f"Host {ip}:{port} has {service} "
                        f"({product or 'unknown'} {version or 'unknown version'}) exposed."
                    ),
                    "remediation": "Review if this service needs to be exposed.",
                    "status": "open",
                    "device_type": device_type,
                    "device_vendor": device_vendor,
                })
                finding_id += 1

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))
    return findings


def classify_devices(xml_path: str) -> dict[str, dict]:
    """Run topology.py + device-classifier.py and return {ip: {device_type, device_vendor}}."""
    scripts_dir = Path(__file__).resolve().parent.parent / "skills" / "site-assessment-pipeline" / "scripts"
    topology_py = scripts_dir / "topology.py"
    classifier_py = scripts_dir / "device-classifier.py"

    try:
        topo = subprocess.run(
            [sys.executable, str(topology_py), xml_path, "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if topo.returncode != 0:
            print(f"  Warning: topology.py failed: {topo.stderr[:200]}", file=sys.stderr)
            return {}

        # Write topology JSON to temp file for device-classifier (doesn't accept stdin)
        topo_fd, topo_path = tempfile.mkstemp(suffix=".json", prefix="portshim-topo-")
        os.write(topo_fd, topo.stdout.encode())
        os.close(topo_fd)
        topo_file = Path(topo_path)
        try:
            classified = subprocess.run(
                [sys.executable, str(classifier_py), "--json", str(topo_file)],
                capture_output=True, text=True, timeout=30,
            )
        finally:
            topo_file.unlink(missing_ok=True)
        if classified.returncode != 0:
            print(f"  Warning: device-classifier.py failed: {classified.stderr[:200]}", file=sys.stderr)
            return {}

        data = json.loads(classified.stdout)
        result = {}
        for host in data.get("hosts", []):
            ip = host.get("ip")
            if ip:
                result[ip] = {
                    "device_type": host.get("device_role", ""),
                    "device_vendor": host.get("device_vendor", ""),
                }
        return result

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, TypeError, ValueError) as e:
        print(f"  Warning: device classification failed: {e}", file=sys.stderr)
        return {}


def main():
    parser = argparse.ArgumentParser(
        description="Generate findings.json from nmap scan with NVD CVE verification"
    )
    parser.add_argument("xml_path", help="Path to nmap XML output (phase1-nmap.xml)")
    parser.add_argument("--output", "-o", default="findings.json",
                        help="Output path (default: findings.json)")
    parser.add_argument("--no-nvd", action="store_true",
                        help="Skip NVD verification (use nmap vulners data only)")
    parser.add_argument("--topology", action="store_true",
                        help="Run device classification and add device_type/device_vendor to findings")
    args = parser.parse_args()

    if not Path(args.xml_path).exists():
        print(f"Error: {args.xml_path} not found", file=sys.stderr)
        sys.exit(1)

    api_key = load_nvd_api_key()

    if not args.no_nvd and not api_key:
        print("Note: No NVD_API_KEY set. Using unauthenticated rate limit (5 req/30s).", file=sys.stderr)
        print("  Set NVD_API_KEY for 50 req/30s.", file=sys.stderr)

    print(f"Parsing {args.xml_path}...", file=sys.stderr)
    hosts = parse_nmap_xml(args.xml_path)
    total_cves = sum(len(h["cves"]) for h in hosts)
    hosts_with_cves = sum(1 for h in hosts if h["cves"])
    print(f"  {len(hosts)} host:port entries, {total_cves} CVEs across {hosts_with_cves} hosts", file=sys.stderr)

    use_nvd = not args.no_nvd
    if use_nvd and total_cves > 0:
        est_time = total_cves * RATE_LIMIT_SLEEP
        print(f"  NVD verification: ~{total_cves} API calls, ~{est_time}s (set NVD_API_KEY for faster)", file=sys.stderr)

    # Device classification
    device_data = {}
    if args.topology:
        print(f"  Running device classification...", file=sys.stderr)
        device_data = classify_devices(args.xml_path)
        classified = sum(1 for d in device_data.values() if d.get("device_type"))
        print(f"  {classified} devices classified", file=sys.stderr)

    findings = generate_findings(hosts, use_nvd=use_nvd, api_key=api_key,
                                 device_data=device_data)

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)

    sev_counts = {}
    for fg in findings:
        s = fg["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    print(f"\nGenerated {len(findings)} findings → {args.output}", file=sys.stderr)
    for s in ["critical", "high", "medium", "low", "info", "unverified"]:
        if s in sev_counts:
            print(f"  {s}: {sev_counts[s]}", file=sys.stderr)


def lookup_exploit(cve_id: str) -> list[dict]:
    """Query searchsploit for exploits matching a CVE ID.

    Returns list of {title, path} dicts, or empty list.
    Results are cached per CVE to avoid redundant searchsploit calls.
    """
    if not hasattr(lookup_exploit, "_cache"):
        lookup_exploit._cache = {}

    if cve_id in lookup_exploit._cache:
        return lookup_exploit._cache[cve_id]
    try:
        result = subprocess.run(
            ["searchsploit", "--cve", cve_id, "-w"],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    exploits = []
    in_table = False
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        if "Exploit Title" in line:
            in_table = True
            continue
        if "Shellcodes:" in line:
            break
        if in_table and "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                exploits.append({
                    "title": parts[0],
                    "path": parts[1] if len(parts) > 1 else "",
                })

    lookup_exploit._cache[cve_id] = exploits
    return exploits


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
device-classifier.py — Classify network hosts by device role and apply targeted checks.

Takes topology JSON (from topology.py) and enriches each host with:
  - device_role: firewall, switch, iot-camera, nvr, wifi-controller, printer,
                 home-automation, voip, storage-nas, industrial-ics, domain-controller,
                 database-mssql, database-oracle, mail-exchange, hypervisor-esxi,
                 certificate-authority, backup-veeam, monitoring, desktop, server, unknown
  - device_vendor: Cisco, Hikvision, Ubiquiti, TP-Link, etc. (from MAC OUI + service fingerprint)
  - default_creds_check: whether the device class is known to ship with default credentials
  - targeted_notes: device-type-specific assessment recommendations

Usage:
    python device-classifier.py topology.json                        # Print enriched table
    python device-classifier.py topology.json --json                 # JSON output
    python device-classifier.py topology.json --findings             # Flag high-risk devices
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
import hashlib
from datetime import datetime

LLM_CACHE = {}  # Cache LLM responses per host signature to avoid re-querying


def classify_with_llm(host: dict) -> tuple[str | None, str | None]:
    """Ask llama-server to classify an unknown device. Returns (role, vendor) or (None, None)."""
    # Build host signature for caching
    ports_str = ",".join(sorted(str(p["port"]) for p in host.get("ports", []) if p.get("state") == "open"))
    sig = f"{host.get('ip','')}|{ports_str}|{host.get('mac_vendor','')}|{host.get('os','')}"
    sig_hash = hashlib.md5(sig.encode()).hexdigest()[:8]

    if sig_hash in LLM_CACHE:
        return LLM_CACHE[sig_hash]

    # Build prompt
    hostname = host.get("hostname", "") or "none"
    mac_vendor = host.get("mac_vendor", "") or "unknown"
    os_guess = host.get("os", "") or "none"
    services = []
    for p in host.get("ports", []):
        if p.get("state") == "open":
            svc = f"{p.get('port')}/{p.get('protocol','tcp')} {p.get('service','?')}"
            if p.get("product"):
                svc += f" ({p.get('product')}"
                if p.get("version"):
                    svc += f" {p.get('version')}"
                svc += ")"
            services.append(svc)

    prompt = (
        "Classify this network device based on fingerprint data. "
        "Respond with ONLY a JSON object: {\"role\": \"...\", \"vendor\": \"...\"}. "
        "Use lowercase-hyphenated roles from: server-linux, server-windows, "
        "network-device, wifi-controller, iot-embedded, iot-smart, media-streaming, "
        "printer, nvr-camera, home-automation, mobile-android, unknown. "
        "Use the most specific role you can determine. "
        "Prioritise MAC vendor and service product over nmap OS guess when they disagree. "
        "Vendor is the manufacturer name.\n\n"
        f"Host: {host.get('ip')}\n"
        f"Hostname: {hostname}\n"
        f"MAC vendor: {mac_vendor}\n"
        f"OS guess: {os_guess}\n"
        f"Services: {', '.join(services) if services else 'none'}"
    )

    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8080/v1/chat/completions",
            data=json.dumps({
                "model": "local",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 200,
                "stream": False,
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        content = data["choices"][0]["message"]["content"].strip()
        # Gemma-4 models put output in reasoning_content instead of content
        if not content:
            content = data["choices"][0]["message"].get("reasoning_content", "").strip()

        # Extract JSON from response (may have markdown wrapping)
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        result = json.loads(content)
        role = result.get("role", "unknown")
        vendor = result.get("vendor", "")
        LLM_CACHE[sig_hash] = (role, vendor)
        return role, vendor

    except (urllib.error.URLError, json.JSONDecodeError, KeyError,
            IndexError, OSError, ValueError) as e:
        print(f"  Warning: LLM classification failed: {e}", file=sys.stderr)
        LLM_CACHE[sig_hash] = (None, None)
        return None, None

# Port-based device signatures: (port_set, title_pattern, vendor, role)
DEVICE_SIGNATURES = [
    # WiFi Controllers
    ({80, 443, 8088, 8043, 8843}, "UniFi", "Ubiquiti", "wifi-controller"),
    ({80, 443, 8088}, "Omada", "TP-Link", "wifi-controller"),
    ({80, 443, 8443}, "Aruba", "HPE/Aruba", "wifi-controller"),
    ({80, 443, 8443}, "Cisco Meraki", "Cisco", "wifi-controller"),
    ({80, 443}, "Ruckus", "Ruckus", "wifi-controller"),

    # Network Infrastructure
    ({22, 80, 443, 161}, None, None, "switch-managed"),
    ({22, 23, 80, 443, 161}, None, None, "switch-managed"),
    ({80, 443, 161, 199, 443}, "pfSense", "Netgate", "firewall"),
    ({80, 443, 22}, "OPNsense", "Deciso", "firewall"),
    ({80, 443, 8443}, "FortiGate", "Fortinet", "firewall"),
    ({80, 443, 22, 161}, "Cisco ASA", "Cisco", "firewall"),
    ({80, 443, 444}, "Sophos", "Sophos", "firewall"),

    # NVRs / Surveillance
    ({80, 554, 8000}, None, "Hikvision", "nvr-camera"),
    ({80, 443, 554}, "Hikvision", "Hikvision", "nvr-camera"),
    ({80, 554, 37777}, None, "Dahua", "nvr-camera"),
    ({80, 443, 554}, "Dahua", "Dahua", "nvr-camera"),
    ({80, 443, 7443}, "UniFi Protect", "Ubiquiti", "nvr-camera"),
    ({80, 554}, "Axis", "Axis", "nvr-camera"),

    # IoT / Smart Home
    ({8123}, "Home Assistant", "Home Assistant", "home-automation"),
    ({80, 443, 8123}, None, None, "home-automation"),
    ({1883, 8883}, None, None, "iot-mqtt"),
    ({80, 8080, 8443}, "Homebridge", "Homebridge", "home-automation"),
    ({80, 443, 5020}, "Control4", "Control4", "office-automation"),
    ({80, 443, 41794}, "Crestron", "Crestron", "office-automation"),

    # Printers
    ({80, 443, 515, 631, 9100}, None, None, "printer"),
    ({80, 443, 631}, None, None, "printer"),
    ({80, 9100}, None, None, "printer"),
    ({80, 443, 161, 9100}, None, None, "printer-mfp"),

    # Storage / NAS
    ({80, 443, 5000, 5001}, "Synology", "Synology", "storage-nas"),
    ({80, 443, 8080, 8443}, "QNAP", "QNAP", "storage-nas"),
    ({80, 443, 548, 445}, None, None, "storage-nas"),
    ({80, 443, 8006}, "Proxmox", "Proxmox", "virtualization"),

    # VoIP
    ({5060, 5061}, None, None, "voip"),
    ({80, 443, 5060, 5061}, None, None, "voip-pbx"),

    # Industrial / OT / ICS
    ({502}, None, None, "industrial-ics"),       # Modbus
    ({102}, None, None, "industrial-ics"),       # Siemens S7
    ({44818}, None, None, "industrial-ics"),      # EtherNet/IP
    ({80, 443, 502, 102}, None, None, "industrial-ics"),
    ({80, 443, 4840}, None, None, "industrial-ics"),  # OPC-UA

    # Building Automation
    ({47808}, None, None, "building-automation"),  # BACnet
    ({80, 443, 47808}, None, None, "building-automation"),

    # Databases
    ({3306}, None, None, "database"),
    ({5432}, None, None, "database"),
    ({1433}, None, None, "database"),
    ({27017}, None, None, "database"),
    ({6379}, None, None, "database"),

    # Common desktops/servers (catch-all)
    ({22}, None, None, "server-linux"),
    ({3389}, None, None, "desktop-windows"),
    ({22, 3389}, None, None, "server-windows"),
    ({80, 443}, None, None, "web-server"),

    # ── Web Servers (identified by tech/title) ──
    ({80, 443, 8080}, "Apache", "Apache", "web-apache"),
    ({80, 443, 8080, 8443}, "nginx", "nginx", "web-nginx"),
    ({80, 443, 8172}, "IIS", "Microsoft", "web-iis"),
    ({80, 443}, "Microsoft-IIS", "Microsoft", "web-iis"),
    ({80, 443, 8080, 8443}, "Caddy", "Caddy", "web-caddy"),
    ({80, 443, 7080, 8088}, "LiteSpeed", "LiteSpeed", "web-litespeed"),
    ({80, 443, 8080}, "Lighttpd", "Lighttpd", "web-lighttpd"),
    ({80, 443, 8080, 8443}, "Jetty", "Eclipse", "web-jetty"),
    ({80, 443, 8080}, "JBoss", "Red Hat", "web-jboss"),
    ({80, 443, 4848}, "GlassFish", "Oracle", "web-glassfish"),
    ({80, 443, 8080}, "WildFly", "Red Hat", "web-wildfly"),

    # ── Critical Infrastructure ──

    # Domain Controllers
    ({88, 389, 636, 3268, 3269}, None, None, "domain-controller"),
    ({88, 389, 445, 139}, None, None, "domain-controller"),
    ({88, 389}, None, None, "domain-controller"),
    ({389, 636, 3268, 3269}, None, None, "domain-controller-ldap"),

    # Certificate Services
    ({80, 443, 389}, "AD CS", "Microsoft", "certificate-authority"),
    ({80, 443, 389}, "Certificate", None, "certificate-authority"),

    # Database Servers (beyond the generic DB catch-all)
    ({1433, 1434}, None, None, "database-mssql"),
    ({1433}, None, None, "database-mssql"),
    ({1521}, None, None, "database-oracle"),
    ({5432, 3306}, None, None, "database-multi"),
    ({27017, 27018, 27019}, None, None, "database-mongodb"),
    ({6379, 6380}, None, None, "database-redis"),
    ({9200, 9300}, None, None, "database-elasticsearch"),

    # Mail / Exchange
    ({25, 80, 443, 587, 993}, "Exchange", "Microsoft", "mail-exchange"),
    ({25, 80, 443, 587}, "Outlook Web", "Microsoft", "mail-exchange"),
    ({25, 80, 443, 587, 135}, None, "Microsoft", "mail-exchange"),
    ({80, 443, 444, 808, 6001, 6002, 6003, 6004}, None, "Microsoft", "mail-exchange-dag"),
    ({80, 443, 2525, 587}, None, "Microsoft", "mail-exchange-edge"),
    ({80, 443, 50636}, None, None, "mail-exchange-edgesync"),
    ({25, 80, 443}, None, None, "mail-server-web"),
    ({25, 587, 993}, None, None, "mail-server"),
    ({25, 80, 443, 587}, None, None, "mail-server"),
    ({25, 110, 143, 993, 995}, None, None, "mail-server"),
    ({25, 80, 443, 587, 993}, None, None, "mail-server"),

    # Application Servers
    ({80, 443, 8080, 8443, 8009}, "Tomcat", "Apache", "app-server-tomcat"),
    ({80, 443, 8009}, None, None, "app-server-java"),
    ({80, 443, 8000}, None, None, "app-server"),
    ({80, 443, 3000}, None, None, "app-server-node"),
    ({80, 443, 5000}, None, None, "app-server-python"),

    # File Servers
    ({139, 445}, None, None, "file-server-smb"),
    ({2049}, None, None, "file-server-nfs"),
    ({139, 445, 2049}, None, None, "file-server"),

    # Virtualization / Hypervisors
    ({443, 902}, None, None, "hypervisor-esxi"),
    ({8006}, None, None, "hypervisor-proxmox"),
    ({80, 443, 8006}, None, None, "hypervisor-proxmox"),
    ({80, 443, 16509}, "Xen", "Citrix", "hypervisor-xen"),
    ({135, 5985, 5986, 2179}, None, None, "hypervisor-hyperv"),
    ({135, 2179}, None, None, "hypervisor-hyperv"),
    ({80, 443, 2179, 5985}, None, None, "hypervisor-hyperv"),

    # Backup Systems
    ({9392}, None, None, "backup-veeam"),
    ({10000}, "Veeam", "Veeam", "backup-veeam"),
    ({80, 443, 4443}, "Veeam", "Veeam", "backup-veeam"),
    ({135, 5718, 5719, 6075}, None, None, "backup-dpm"),
    ({5718, 5719}, None, None, "backup-dpm"),
    ({6075}, None, None, "backup-dpm"),
    ({80, 443, 6075, 5718}, None, None, "backup-dpm"),

    # Monitoring / Management
    ({161, 162}, None, None, "monitoring-snmp"),
    ({80, 443, 3000}, "Grafana", "Grafana", "monitoring-grafana"),
    ({9090}, None, None, "monitoring-prometheus"),
    ({80, 443, 9090}, None, None, "monitoring-prometheus"),
    ({80, 443, 9093}, None, None, "monitoring-alertmanager"),
    ({5666}, None, None, "monitoring-nagios"),
    ({80, 443, 10000}, None, None, "monitoring-webmin"),
    ({80, 443, 15672}, None, None, "message-queue-rabbitmq"),

    # Remote Access / Jump Boxes
    ({22, 3389, 443}, None, None, "remote-access-jumpbox"),
    ({80, 443, 5938}, None, None, "remote-access-teamviewer"),
    ({80, 443, 4000}, None, None, "remote-access-anydesk"),
]

# Device classes known to commonly ship with default credentials
DEFAULT_CREDS_CLASSES = {
    "nvr-camera", "wifi-controller", "printer", "printer-mfp",
    "storage-nas", "iot-mqtt", "switch-managed", "firewall",
    "home-automation", "voip-pbx", "industrial-ics",
    "database-mssql", "database-oracle", "database-mongodb", "database-redis",
    "hypervisor-esxi", "hypervisor-hyperv", "backup-veeam", "backup-dpm",
}

# High-value targets that warrant immediate attention
HIGH_VALUE_CLASSES = {
    "nvr-camera", "firewall", "switch-managed", "wifi-controller",
    "industrial-ics", "office-automation", "building-automation",
    "domain-controller", "domain-controller-ldap", "certificate-authority",
    "mail-exchange", "mail-exchange-dag", "mail-exchange-edge", "mail-exchange-edgesync", "database-mssql", "database-oracle", "database-multi",
    "web-apache", "web-nginx", "web-iis", "web-jboss",
    "hypervisor-esxi", "hypervisor-proxmox", "hypervisor-hyperv", "backup-veeam", "backup-dpm",
    "remote-access-jumpbox",
}

# MAC OUI → vendor quick lookup (common ones — full OUI database is 30K+ entries)
MAC_VENDORS = {
    "00:15:6D": "Ubiquiti",
    "00:1F:9F": "Cisco",
    "00:25:9C": "Cisco",
    "00:0E:08": "Dahua",
    "00:40:8C": "Axis",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:11:32": "Synology",
    "00:08:9B": "Netgear",
    "00:1B:2F": "Netgear",
    "00:24:8D": "Hikvision",
    "AC:CC:8E": "Hikvision",
    "18:E8:29": "TP-Link",
    "00:0C:43": "TP-Link",
    "28:87:BA": "TP-Link",
    "58:04:4F": "TP-Link",
    "B0:3A:F2": "Amazon",
    "F0:81:AF": "Google",
    "00:1A:11": "Google",
    "00:17:88": "Philips",
    "00:17:F2": "Apple",
    "00:1B:63": "Apple",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "00:80:F4": "Telemecanique",
}


# MAC vendor → default role when no port-pattern match exists
MAC_VENDOR_ROLES = {
    "Hikvision": "nvr-camera",
    "Dahua": "nvr-camera",
    "Axis": "nvr-camera",
    "TP-Link": "network-device",
    "Ubiquiti": "wifi-controller",
    "Synology": "storage-nas",
    "QNAP": "storage-nas",
    "Amazon": "iot-smart",
    "Google": "iot-smart",
    "Philips": "iot-lighting",
    "Raspberry Pi": "iot-dev-board",
    "Telemecanique": "industrial-ics",
}


def classify_host(host: dict) -> dict:
    """Classify a single host by device type."""
    ports = {p["port"] for p in host.get("ports", []) if p["state"] == "open"}
    port_ints = set()
    for p in ports:
        if p.isdigit():
            num = int(p)
            if 1 <= num <= 65535:
                port_ints.add(num)

    # Get HTTP title from first open web port
    web_title = ""
    for p in host.get("ports", []):
        if p.get("port") in ("80", "443", "8080", "8443"):
            web_title = p.get("title", "")
            if web_title:
                break

    # Match against device signatures
    best_match = None
    best_score = 0
    for sig_ports, sig_title, sig_vendor, sig_role in DEVICE_SIGNATURES:
        if not port_ints:
            continue
        overlap = port_ints & sig_ports
        if not overlap:
            continue
        # If signature has a title pattern, require it to match
        if sig_title and (not web_title or sig_title.lower() not in web_title.lower()):
            continue
        score = len(overlap)
        # Bonus for title match (already gated above, but keep for scoring)
        if sig_title and web_title and sig_title.lower() in web_title.lower():
            score += 10
        if score > best_score:
            best_score = score
            best_match = (sig_vendor, sig_role)

    # MAC vendor
    mac = host.get("mac", "")
    mac_vendor = None
    if mac:
        oui = mac[:8].upper()
        mac_vendor = MAC_VENDORS.get(oui)

    # Determine final classification
    vendor = None
    role = "unknown"
    if best_match:
        vendor, role = best_match

    # Hostname-based overrides — more reliable than port patterns
    hostname = (host.get("hostname") or "").lower()
    os_guess = (host.get("os") or "").lower()

    # Android devices
    if hostname.startswith("android"):
        role = "mobile-android"
        vendor = "Google"
    # Home Assistant
    elif "homeassistant" in hostname or "home-assistant" in hostname:
        role = "home-automation"
        vendor = "Home Assistant"
    # Known Linux distros — never switches
    elif any(distro in hostname for distro in (
        "ubuntu", "debian", "cachy", "fedora", "centos", "rhel",
        "arch", "manjaro", "opensuse", "raspbian", "kali", "mint",
        "precibuntu",  # Ubuntu variant
    )):
        role = "server-linux"
        vendor = vendor or "Linux"
    # Override switch classification if hostname suggests otherwise
    elif role == "switch-managed" and any(word in hostname for word in (
        "ubuntu", "debian", "cachy", "fedora", "linux", "server",
        "precibuntu", "desktop", "laptop", "workstation",
    )):
        role = "server-linux"

    # MAC vendor role inference — reliable for well-known vendors
    if role in ("unknown", "wifi-controller", "switch-managed"):
        # Try MAC_VENDORS OUI first, then topology mac_vendor as fallback
        vendor_lookup = (mac_vendor or host.get("mac_vendor") or "")
        # Normalize: strip "Systems"/"Corporate"/"Technologies" suffixes
        vendor_lookup = vendor_lookup.replace(" Systems", "").replace(" Corporate", "").replace(" Technologies", "")
        inferred_role = MAC_VENDOR_ROLES.get(vendor_lookup)
        if inferred_role:
            role = inferred_role
            vendor = vendor or vendor_lookup

    # LLM fallback for remaining ambiguous devices
    if role in ("unknown", "wifi-controller", "switch-managed"):
        llm_role, llm_vendor = classify_with_llm(host)
        if llm_role:
            role = llm_role
            vendor = llm_vendor or vendor

    host["device_role"] = role
    host["device_vendor"] = vendor or host.get("mac_vendor", "unknown")
    host["has_default_creds_risk"] = role in DEFAULT_CREDS_CLASSES
    host["is_high_value"] = role in HIGH_VALUE_CLASSES

    # Targeted notes
    notes = []
    if role == "nvr-camera":
        notes.append("Check for default admin credentials. Common: admin/admin, admin/12345.")
        notes.append("Check for exposed RTSP streams (port 554) without authentication.")
        notes.append("Check firmware version — many NVRs have unauthenticated RCE CVEs.")
    elif role == "wifi-controller":
        notes.append("Check controller version — many have API info leaks at /api/info or /status.")
        notes.append("Check for default credentials: ubnt/ubnt (UniFi), admin/admin (Omada).")
        notes.append("Managed APs may expose SSH with default keys.")
    elif role == "firewall":
        notes.append("Check for management interface exposure on WAN-facing IPs.")
        notes.append("Check for known CVEs on the specific firmware version.")
        notes.append("Check for default credentials or weak admin passwords.")
    elif role == "switch-managed":
        notes.append("Check for default telnet/SSH credentials.")
        notes.append("SNMP community strings may be default (public/private).")
        notes.append("Check for outdated firmware with known CVEs.")
    elif role == "home-automation":
        notes.append("Check if Home Assistant (8123) has authentication enabled.")
        notes.append("Check for exposed MQTT broker (1883) without authentication.")
        notes.append("Smart home hubs may bridge to physical security (locks, alarms).")
    elif role == "office-automation":
        notes.append("Control4/Crestron systems often have default installer credentials.")
        notes.append("These systems control lighting, HVAC, AV — compromise = physical access.")
        notes.append("Check for exposed configuration APIs.")
    elif role == "printer":
        notes.append("Check for default admin credentials on web interface.")
        notes.append("Check for exposed JetDirect (9100) without authentication.")
        notes.append("Printers often retain copies of printed documents in memory.")
    elif role == "storage-nas":
        notes.append("Check for default admin credentials.")
        notes.append("Check for exposed SMB shares without authentication.")
        notes.append("NAS devices often contain sensitive data and backups.")
    elif role == "industrial-ics":
        notes.append("Industrial protocols (Modbus, S7, EtherNet/IP) often have no authentication.")
        notes.append("Treat with extreme caution — do NOT send write commands without authorization.")
        notes.append("These devices control physical processes — compromise has safety implications.")
    elif role == "building-automation":
        notes.append("BACnet devices often have no authentication.")
        notes.append("Building automation controls HVAC, access control, lighting.")
        notes.append("Check if the BACnet router is exposed to the general network.")
    elif role == "domain-controller" or role == "domain-controller-ldap":
        notes.append("Primary authentication source for the domain.")
        notes.append("Check for LDAP signing not enforced — enables relay attacks.")
        notes.append("Check Kerberos configuration — old encryption types (RC4) weaken security.")
        notes.append("LDAP without channel binding is vulnerable to NTLM relay.")
        notes.append("Exposed LDAP/GC ports to non-domain subnets is a finding.")
    elif role == "certificate-authority":
        notes.append("Compromise of a CA allows forging certificates for any host.")
        notes.append("Check for AD CS vulnerabilities: ESC1-ESC13 attack paths.")
        notes.append("Check if certificate templates allow client authentication via low-priv users.")
    elif role == "database-mssql":
        notes.append("Check for default SA account with weak password.")
        notes.append("Check if xp_cmdshell is enabled — allows command execution.")
        notes.append("SQL Server ports exposed to non-app subnets is a finding.")
        notes.append("Check for unpatched versions with known RCE CVEs.")
    elif role == "database-oracle":
        notes.append("Check for default accounts: SCOTT/TIGER, SYSTEM/MANAGER, DBSNMP/DBSNMP.")
        notes.append("Oracle TNS listener (1521) often exposes version and SID info without auth.")
        notes.append("Check for outdated versions with known TNS poisoning vulnerabilities.")
    elif role == "database-mongodb":
        notes.append("MongoDB prior to 3.6 had no authentication enabled by default.")
        notes.append("Check if MongoDB is exposed without auth — allows full database access.")
    elif role == "database-redis":
        notes.append("Redis often runs without password by default on port 6379.")
        notes.append("Unauthenticated Redis allows reading/writing all keys and writing SSH keys.")
    elif role == "database-elasticsearch":
        notes.append("Elasticsearch prior to 6.8/7.1 had no security features enabled by default.")
        notes.append("Check for exposed Elasticsearch without authentication.")
    elif role == "web-apache":
        notes.append("Check Apache version via Server header or /server-info /server-status.")
        notes.append("Check for directory listing enabled (Options +Indexes).")
        notes.append("Check for default Apache welcome page — indicates unconfigured deployment.")
        notes.append("Check for mod_status exposed without authentication.")
    elif role == "web-nginx":
        notes.append("Check nginx version — many CVEs for older releases.")
        notes.append("Check for misconfigured proxy_pass allowing SSRF.")
        notes.append("Check for alias traversal and off-by-slash path confusion.")
        notes.append("Check /nginx_status for stub status page exposure.")
    elif role == "web-iis":
        notes.append("Check IIS version via Server header — IIS 6.0 and 7.0 have critical CVEs.")
        notes.append("Check for WebDAV enabled with PUT/MOVE methods allowing file uploads.")
        notes.append("Check for ASP.NET tracing enabled (/Trace.axd).")
        notes.append("Check for exposed management interface on port 8172.")
    elif role == "web-jboss":
        notes.append("Check JBoss JMX console for default credentials (admin/admin).")
        notes.append("JMX console allows deploying arbitrary WAR files = RCE.")
        notes.append("Check for exposed /jmx-console/ and /web-console/ without authentication.")
    elif role == "web-caddy":
        notes.append("Check Caddy admin API (default port 2019) for unauthorized access.")
        notes.append("Admin API allows dynamic config changes including route manipulation.")
    elif role == "web-glassfish":
        notes.append("Check for default admin credentials on port 4848 (admin/adminadmin).")
        notes.append("GlassFish admin console allows deploying applications = RCE.")
    elif role == "mail-exchange" or role.startswith("mail-exchange"):
        notes.append("Exchange servers have large attack surface: EWS, OWA, ECP, RPC, ActiveSync.")
        notes.append("Check for ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207) — unauthenticated RCE.")
        notes.append("Check for ProxyLogon (CVE-2021-26855) — SSRF leading to privesc.")
        notes.append("OWA/ECP may disclose internal domain name and exact Exchange build number.")
        notes.append("Check /owa/auth/ for version disclosure without authentication.")
        notes.append("Check /autodiscover/ for internal service URL leakage.")
        notes.append("Check /ecp/ for exposed admin control panel.")
    elif role == "mail-exchange-dag":
        notes.append("Database Availability Group — holds replicated mailbox databases.")
        notes.append("DAG replication ports (6001-6004) may traverse firewalls unrestricted.")
        notes.append("Compromise of one DAG member = access to all replicated mailboxes.")
    elif role == "mail-exchange-edge":
        notes.append("Edge Transport server sits in DMZ — internet-facing mail relay.")
        notes.append("Check for open relay configuration on port 25/2525.")
        notes.append("Edge servers often have less monitoring than internal Exchange roles.")
    elif role == "mail-exchange-edgesync":
        notes.append("EdgeSync synchronizes Edge Transport with internal Exchange.")
        notes.append("Port 50636 allows inbound sync from DMZ to internal network.")
        notes.append("Compromise of EdgeSync = bridgehead from DMZ into internal Exchange org.")
    elif role == "hypervisor-esxi" or role == "hypervisor-proxmox":
        notes.append("Hypervisor compromise gives access to ALL VMs on that host.")
        notes.append("Check for default root credentials on ESXi/Proxmox.")
        notes.append("Check for outdated versions with known escape vulnerabilities.")
    elif role == "hypervisor-hyperv":
        notes.append("Hyper-V host compromise gives access to all guest VMs.")
        notes.append("Check WinRM (5985/5986) for weak credentials or unencrypted HTTP.")
        notes.append("Check Hyper-V Replica (2179) — may allow VM data interception.")
        notes.append("Hyper-V hosts are often domain-joined — lateral movement vector.")
    elif role == "backup-dpm":
        notes.append("DPM servers hold backups of all protected workloads.")
        notes.append("Check DPM agent ports (5718/5719) — compromise allows data exfiltration.")
        notes.append("DPMRA (6075) may accept connections with weak authentication.")
        notes.append("DPM is often co-located with high-privilege service accounts.")
    elif role == "backup-veeam":
        notes.append("Backup servers contain copies of all critical data.")
        notes.append("Check for default credentials on Veeam Backup & Replication console.")
        notes.append("Veeam credentials can be extracted and used to access backup storage.")
    elif role == "monitoring-grafana" or role == "monitoring-prometheus":
        notes.append("Monitoring systems often have read access to sensitive metrics.")
        notes.append("Check for default admin credentials on Grafana.")
        notes.append("Prometheus may expose internal service endpoints via service discovery.")
    elif role == "remote-access-jumpbox":
        notes.append("Jump boxes provide access to internal network segments.")
        notes.append("Compromise of a jump box often means compromise of the entire management plane.")
        notes.append("Check for exposed RDP (3389) — common target for brute force.")

    host["targeted_notes"] = notes
    return host


def classify_hosts(hosts: list[dict]) -> list[dict]:
    """Classify all hosts by device type."""
    return [classify_host(h) for h in hosts]


def render_classified_table(hosts: list[dict]) -> str:
    """Pretty-print classified topology table."""
    lines = [
        f"Device Classification Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"{'IP':<16} {'Role':<22} {'Vendor':<16} {'Open Ports':<30} {'Risk'}",
        "-" * 110,
    ]

    for host in hosts:
        ip = host.get("ip", "?")
        role = host.get("device_role", "unknown")
        vendor = (host.get("device_vendor") or "")[:15]
        ports_str = ",".join(str(p["port"]) for p in host.get("ports", []))

        risk_flags = []
        if host.get("has_default_creds_risk"):
            risk_flags.append("[DEFAULT CREDS]")
        if host.get("is_high_value"):
            risk_flags.append("[HIGH VALUE]")

        lines.append(
            f"{ip:<16} {role:<22} {vendor:<16} {ports_str:<30} {' '.join(risk_flags)}"
        )

    lines.append("-" * 110)

    # Summary
    roles = {}
    for h in hosts:
        r = h.get("device_role", "unknown")
        roles[r] = roles.get(r, 0) + 1

    high_value = sum(1 for h in hosts if h.get("is_high_value"))
    default_cred_risk = sum(1 for h in hosts if h.get("has_default_creds_risk"))

    lines.append(f"Total: {len(hosts)} hosts | High-value: {high_value} | Default cred risk: {default_cred_risk}")
    lines.append("Roles: " + ", ".join(f"{k}={v}" for k, v in sorted(roles.items())))

    return "\n".join(lines)


def render_findings(hosts: list[dict]) -> str:
    """Output actionable findings for high-risk devices."""
    findings = []
    for host in hosts:
        if not host.get("is_high_value") and not host.get("has_default_creds_risk"):
            continue
        findings.append(
            f"[{host.get('device_role', '?').upper()}] {host['ip']} — {host.get('device_vendor', 'unknown')}"
        )
        for note in host.get("targeted_notes", []):
            findings.append(f"  -> {note}")
        findings.append("")
    return "\n".join(findings) if findings else "No high-risk devices found."


def main():
    parser = argparse.ArgumentParser(description="Classify network hosts by device type")
    parser.add_argument("topology", help="Topology JSON from topology.py")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--findings", action="store_true", help="Only show actionable findings")
    args = parser.parse_args()

    with open(args.topology) as f:
        data = json.load(f)
        hosts = data.get("hosts", data) if isinstance(data, dict) else data

    classified = classify_hosts(hosts)

    if args.json:
        print(json.dumps({
            "scan_date": datetime.now().isoformat(),
            "host_count": len(classified),
            "hosts": classified,
        }, indent=2))
    elif args.findings:
        print(render_findings(classified))
    else:
        print(render_classified_table(classified))


if __name__ == "__main__":
    main()

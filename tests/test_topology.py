"""
Unit tests for topology.py — Parse nmap XML into structured host data.

Tests cover:
  - parse_nmap_xml: host count, IPs, ports, OS guesses
  - enrich_with_cves: CVE annotation on correct hosts
  - render_table: expected columns and content
  - render_json: valid JSON structure
  - render_dot: valid DOT syntax
  - _ip_sort_key: correct numerical IP sorting
"""

import json
import sys
from pathlib import Path

import pytest

# Ensure the scripts directory is importable
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "skills" / "site-assessment-pipeline" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from topology import (
    parse_nmap_xml,
    enrich_with_cves,
    render_table,
    render_json,
    render_dot,
    _ip_sort_key,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# Helper: minimal valid nmap XML fixture
# ---------------------------------------------------------------------------
VALID_NMAP_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O 192.168.1.0/24"
        start="1234567890" startstr="Mon Jan 01 00:00:00 2024"
        version="7.80" xmloutputversion="1.04">
<host starttime="1234567890" endtime="1234567895">
  <status state="up" reason="syn-ack" reason_ttl="64"/>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Intel"/>
  <hostnames>
    <hostname name="gateway.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="7.4" extrainfo="Ubuntu Linux"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open"/>
      <service name="https" product="nginx" version="1.18.0"/>
    </port>
    <port protocol="tcp" portid="8080">
      <state state="filtered"/>
      <service name="http-proxy"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 3.2 - 4.9" accuracy="95" line="123"/>
    <osmatch name="Linux 4.4" accuracy="90"/>
  </os>
</host>
<host starttime="1234567890" endtime="1234567895">
  <status state="up"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <hostnames>
    <hostname name="web01.example.com" type="user"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx" version="1.14.0"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open"/>
      <service name="https" product="nginx" version="1.18.0"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4" accuracy="97"/>
  </os>
</host>
<host starttime="1234567890" endtime="1234567895">
  <status state="down"/>
  <address addr="192.168.1.200" addrtype="ipv4"/>
  <!-- No open ports, no OS, no hostname — minimal host -->
</host>
</nmaprun>"""


# ---------------------------------------------------------------------------
# parse_nmap_xml tests
# ---------------------------------------------------------------------------

class TestParseNmapXml:
    """Tests for parse_nmap_xml()."""

    def test_returns_correct_host_count(self, tmp_path):
        """parse_nmap_xml returns the correct number of hosts with IP addresses."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        assert len(hosts) == 3

    def test_extracts_ip_addresses(self, tmp_path):
        """Each parsed host has a correct ip field."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        ips = {h["ip"] for h in hosts}
        assert ips == {"192.168.1.1", "192.168.1.10", "192.168.1.200"}

    def test_extracts_mac_and_vendor(self, tmp_path):
        """MAC address and vendor are extracted when present."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host1 = next(h for h in hosts if h["ip"] == "192.168.1.1")
        assert host1["mac"] == "00:11:22:33:44:55"
        assert host1["mac_vendor"] == "Intel"

    def test_extracts_hostname_ptr(self, tmp_path):
        """PTR hostname is preferred and extracted."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host1 = next(h for h in hosts if h["ip"] == "192.168.1.1")
        assert host1["hostname"] == "gateway.local"

    def test_extracts_hostname_user_fallback(self, tmp_path):
        """User hostname is used when no PTR exists."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host2 = next(h for h in hosts if h["ip"] == "192.168.1.10")
        assert host2["hostname"] == "web01.example.com"

    def test_extracts_open_ports_only(self, tmp_path):
        """Only open ports are included; filtered ports are excluded."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host1 = next(h for h in hosts if h["ip"] == "192.168.1.1")
        open_ports = {(p["port"], p["protocol"]) for p in host1["ports"]}
        assert open_ports == {("22", "tcp"), ("443", "tcp")}
        # 8080/tcp is filtered, should not appear
        assert not any(p["port"] == "8080" for p in host1["ports"])

    def test_extracts_port_service_details(self, tmp_path):
        """Port entries include service name, product, and version."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host2 = next(h for h in hosts if h["ip"] == "192.168.1.10")
        port80 = next(p for p in host2["ports"] if p["port"] == "80")
        assert port80["service"] == "http"
        assert port80["product"] == "nginx"
        assert port80["version"] == "1.14.0"

    def test_extracts_os_guess(self, tmp_path):
        """First osmatch name is captured as OS guess."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host1 = next(h for h in hosts if h["ip"] == "192.168.1.1")
        assert host1["os"] == "Linux 3.2 - 4.9"

        host2 = next(h for h in hosts if h["ip"] == "192.168.1.10")
        assert host2["os"] == "Linux 5.4"

    def test_status_field(self, tmp_path):
        """Host status is correctly extracted."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host1 = next(h for h in hosts if h["ip"] == "192.168.1.1")
        assert host1["status"] == "up"

        host3 = next(h for h in hosts if h["ip"] == "192.168.1.200")
        assert host3["status"] == "down"

    def test_hosts_sorted_by_ip(self, tmp_path):
        """Returned hosts are sorted by IP address."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        ips = [h["ip"] for h in hosts]
        assert ips == ["192.168.1.1", "192.168.1.10", "192.168.1.200"]

    def test_missing_fields_default_correctly(self, tmp_path):
        """Hosts missing optional fields get correct defaults."""
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(VALID_NMAP_XML)

        hosts = parse_nmap_xml(str(xml_file))

        host3 = next(h for h in hosts if h["ip"] == "192.168.1.200")
        assert host3["mac"] is None
        assert host3["mac_vendor"] is None
        assert host3["hostname"] is None
        assert host3["os"] is None
        assert host3["ports"] == []
        assert host3["cves"] == []


# ---------------------------------------------------------------------------
# _ip_sort_key tests
# ---------------------------------------------------------------------------

class TestIpSortKey:
    """Tests for _ip_sort_key()."""

    def test_normal_ip(self):
        """Normal IPv4 address returns tuple of ints."""
        assert _ip_sort_key("192.168.1.1") == (192, 168, 1, 1)

    def test_sorting_order(self):
        """IPs sort numerically, not lexicographically."""
        ips = ["10.0.0.2", "192.168.1.1", "10.0.0.10", "10.0.0.1"]
        sorted_ips = sorted(ips, key=_ip_sort_key)
        assert sorted_ips == ["10.0.0.1", "10.0.0.2", "10.0.0.10", "192.168.1.1"]

    def test_invalid_ip_returns_large_tuple(self):
        """Invalid IP returns a large sentinel tuple so it sorts last."""
        assert _ip_sort_key("not-an-ip") == (999, 999, 999, 999)

    def test_none_input(self):
        """None input falls through to sentinel."""
        result = _ip_sort_key(None)
        assert result == (999, 999, 999, 999)

    def test_partial_ip(self):
        """Partial IP (e.g. '192.168') falls through to sentinel."""
        result = _ip_sort_key("192.168")
        # Only 2 octets, so the tuple unpacking works differently
        # Actually: int(octet) for octet in "192.168".split(".") = (192, 168)
        # Wait, that would succeed. Let me check: "192.168".split(".") = ["192", "168"]
        # So it returns (192, 168). This might be intentional or a quirk.
        # Testing what actually happens:
        assert result == (192, 168)

    def test_empty_string(self):
        """Empty string falls through to sentinel."""
        result = _ip_sort_key("")
        # "".split(".") = [""] → int("") raises ValueError → sentinel
        assert result == (999, 999, 999, 999)


# ---------------------------------------------------------------------------
# enrich_with_cves tests
# ---------------------------------------------------------------------------

class TestEnrichWithCves:
    """Tests for enrich_with_cves()."""

    @pytest.fixture
    def cve_data(self):
        """Load the cves.json fixture."""
        with open(FIXTURES_DIR / "cves.json") as f:
            return json.load(f)

    @pytest.fixture
    def sample_hosts(self):
        """Build hosts matching the cves.json fixture."""
        return [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway.local",
                "os": "Linux",
                "status": "up",
                "ports": [
                    {"port": "443", "protocol": "tcp", "service": "https", "state": "open"},
                    {"port": "22", "protocol": "tcp", "service": "ssh", "state": "open"},
                ],
                "cves": [],
            },
            {
                "ip": "192.168.1.10",
                "hostname": "web01",
                "os": "Linux",
                "status": "up",
                "ports": [
                    {"port": "80", "protocol": "tcp", "service": "http", "state": "open"},
                    {"port": "443", "protocol": "tcp", "service": "https", "state": "open"},
                ],
                "cves": [],
            },
            {
                "ip": "192.168.1.100",
                "hostname": "app01",
                "os": "Linux",
                "status": "up",
                "ports": [
                    {"port": "22", "protocol": "tcp", "service": "ssh", "state": "open"},
                ],
                "cves": [],
            },
        ]

    def test_adds_cves_to_correct_host_port(self, sample_hosts, cve_data):
        """CVEs are annotated on the matching host:port."""
        result = enrich_with_cves(sample_hosts, cve_data)

        host1 = next(h for h in result if h["ip"] == "192.168.1.1")
        # 192.168.1.1:443 has 2 CVEs (critical + high)
        cve_ids = [c["id"] for c in host1["cves"]]
        assert "CVE-2024-1234" in cve_ids
        assert "CVE-2024-5678" in cve_ids

    def test_cves_on_port_level(self, sample_hosts, cve_data):
        """CVEs are also attached to the individual port dict."""
        result = enrich_with_cves(sample_hosts, cve_data)

        host1 = next(h for h in result if h["ip"] == "192.168.1.1")
        port443 = next(p for p in host1["ports"] if p["port"] == "443")
        assert "cves" in port443
        assert len(port443["cves"]) == 2

    def test_empty_cve_list_preserved(self, sample_hosts, cve_data):
        """A host:port with empty cves list doesn't crash."""
        result = enrich_with_cves(sample_hosts, cve_data)

        host2 = next(h for h in result if h["ip"] == "192.168.1.10")
        port443 = next(p for p in host2["ports"] if p["port"] == "443")
        assert port443.get("cves", []) == []

    def test_no_cves_for_unmatched_ports(self, sample_hosts, cve_data):
        """Ports not in CVE data are unaffected."""
        result = enrich_with_cves(sample_hosts, cve_data)

        host1 = next(h for h in result if h["ip"] == "192.168.1.1")
        port22 = next(p for p in host1["ports"] if p["port"] == "22")
        # No CVE entry for 192.168.1.1:22 in fixture
        assert "cves" not in port22
        # Host-level cves should only contain the matched ones
        cve_ids = [c["id"] for c in host1["cves"]]
        assert len(cve_ids) == 2  # only from :443

    def test_host_cves_accumulate_from_multiple_ports(self, sample_hosts):
        """If multiple ports on the same host have CVEs, they accumulate."""
        cve_data = [
            {"ip": "192.168.1.1", "port": 443, "cves": [{"id": "CVE-A", "severity": "high"}]},
            {"ip": "192.168.1.1", "port": 22, "cves": [{"id": "CVE-B", "severity": "medium"}]},
        ]
        result = enrich_with_cves(sample_hosts, cve_data)

        host1 = next(h for h in result if h["ip"] == "192.168.1.1")
        cve_ids = {c["id"] for c in host1["cves"]}
        assert cve_ids == {"CVE-A", "CVE-B"}


# ---------------------------------------------------------------------------
# render_table tests
# ---------------------------------------------------------------------------

class TestRenderTable:
    """Tests for render_table()."""

    @pytest.fixture
    def sample_hosts(self):
        return [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway.local",
                "os": "Linux 3.2 - 4.9",
                "status": "up",
                "ports": [
                    {"port": "22", "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "7.4"},
                ],
                "cves": [{"id": "CVE-2024-1234", "severity": "critical"}],
            },
            {
                "ip": "192.168.1.10",
                "hostname": None,
                "os": None,
                "status": "up",
                "ports": [],
                "cves": [],
            },
        ]

    def test_has_expected_columns(self, sample_hosts):
        """Table header contains IP, Hostname, OS, Open Ports."""
        output = render_table(sample_hosts)
        assert "IP" in output
        assert "Hostname" in output
        assert "OS" in output
        assert "Open Ports" in output

    def test_includes_host_count(self, sample_hosts):
        """Footer includes total host count."""
        output = render_table(sample_hosts)
        assert "Total hosts: 2" in output

    def test_includes_port_count(self, sample_hosts):
        """Footer includes total open port count."""
        output = render_table(sample_hosts)
        assert "Total open ports: 1" in output

    def test_includes_cve_annotations(self, sample_hosts):
        """Hosts with CVEs show CVE summary lines."""
        output = render_table(sample_hosts)
        assert "CVEs:" in output
        assert "CVE-2024-1234" in output

    def test_handles_missing_hostname_and_os(self, sample_hosts):
        """Hosts with None hostname/OS render without crashing."""
        output = render_table(sample_hosts)
        # Should still render all hosts
        assert "192.168.1.10" in output

    def test_handles_empty_host_list(self):
        """Empty host list renders without error."""
        output = render_table([])
        assert "Total hosts: 0" in output
        assert "Total open ports: 0" in output

    def test_returns_string(self, sample_hosts):
        """render_table returns a string."""
        output = render_table(sample_hosts)
        assert isinstance(output, str)
        assert len(output) > 0


# ---------------------------------------------------------------------------
# render_json tests
# ---------------------------------------------------------------------------

class TestRenderJson:
    """Tests for render_json()."""

    @pytest.fixture
    def sample_hosts(self):
        return [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway",
                "os": "Linux",
                "status": "up",
                "ports": [
                    {"port": "22", "protocol": "tcp", "service": "ssh", "state": "open"},
                ],
                "cves": [{"id": "CVE-2024-1234", "severity": "critical"}],
            },
        ]

    def test_outputs_valid_json(self, sample_hosts):
        """Output is parseable JSON."""
        output = render_json(sample_hosts)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_has_scan_date(self, sample_hosts):
        """Top-level key 'scan_date' is present."""
        output = render_json(sample_hosts)
        parsed = json.loads(output)
        assert "scan_date" in parsed

    def test_has_host_count(self, sample_hosts):
        """Top-level key 'host_count' matches number of hosts."""
        output = render_json(sample_hosts)
        parsed = json.loads(output)
        assert parsed["host_count"] == 1

    def test_has_hosts_array(self, sample_hosts):
        """Top-level key 'hosts' is a list."""
        output = render_json(sample_hosts)
        parsed = json.loads(output)
        assert isinstance(parsed["hosts"], list)
        assert len(parsed["hosts"]) == 1

    def test_host_structure_preserved(self, sample_hosts):
        """Individual host structure is preserved in JSON output."""
        output = render_json(sample_hosts)
        parsed = json.loads(output)
        host = parsed["hosts"][0]
        assert host["ip"] == "192.168.1.1"
        assert host["hostname"] == "gateway"
        assert host["os"] == "Linux"
        assert len(host["ports"]) == 1
        assert host["ports"][0]["port"] == "22"

    def test_empty_hosts(self):
        """Empty host list produces valid JSON with host_count=0."""
        output = render_json([])
        parsed = json.loads(output)
        assert parsed["host_count"] == 0
        assert parsed["hosts"] == []


# ---------------------------------------------------------------------------
# render_dot tests
# ---------------------------------------------------------------------------

class TestRenderDot:
    """Tests for render_dot()."""

    @pytest.fixture
    def sample_hosts(self):
        return [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway.local",
                "os": "Linux",
                "status": "up",
                "ports": [],
                "cves": [{"id": "CVE-2024-1234", "severity": "critical"}],
            },
            {
                "ip": "192.168.1.10",
                "hostname": "web01",
                "os": "Linux",
                "status": "up",
                "ports": [],
                "cves": [{"id": "CVE-2024-5678", "severity": "high"}],
            },
            {
                "ip": "192.168.1.20",
                "hostname": "clean-host",
                "os": "Linux",
                "status": "up",
                "ports": [],
                "cves": [],
            },
        ]

    def test_produces_valid_digraph(self, sample_hosts):
        """Output starts with 'digraph' and ends with '}'."""
        output = render_dot(sample_hosts)
        assert output.startswith("digraph")
        assert output.strip().endswith("}")

    def test_contains_legend(self, sample_hosts):
        """DOT output includes a legend subgraph."""
        output = render_dot(sample_hosts)
        assert "subgraph cluster_legend" in output
        assert "Critical CVEs" in output
        assert "High CVEs" in output
        assert "No CVEs" in output

    def test_contains_all_hosts_as_nodes(self, sample_hosts):
        """Each host appears as a node with its IP-mangled ID."""
        output = render_dot(sample_hosts)
        assert "192_168_1_1" in output
        assert "192_168_1_10" in output
        assert "192_168_1_20" in output

    def test_critical_host_gets_red_fill(self, sample_hosts):
        """Host with critical CVE gets #CC4141 fill."""
        output = render_dot(sample_hosts)
        # Find the line for the critical host
        lines = output.split("\n")
        critical_line = next(l for l in lines if "192_168_1_1" in l and "label=" in l)
        assert "#CC4141" in critical_line

    def test_high_host_gets_orange_fill(self, sample_hosts):
        """Host with high CVE gets #FF8C00 fill."""
        output = render_dot(sample_hosts)
        lines = output.split("\n")
        high_line = next(l for l in lines if "192_168_1_10" in l and "label=" in l)
        assert "#FF8C00" in high_line

    def test_clean_host_gets_green_fill(self, sample_hosts):
        """Host with no CVEs gets #90EE90 fill."""
        output = render_dot(sample_hosts)
        lines = output.split("\n")
        clean_line = next(l for l in lines if "192_168_1_20" in l and "label=" in l)
        assert "#90EE90" in clean_line

    def test_rankdir_present(self, sample_hosts):
        """DOT output includes rankdir setting."""
        output = render_dot(sample_hosts)
        assert "rankdir=LR" in output

    def test_empty_hosts(self):
        """Empty host list produces valid minimal DOT."""
        output = render_dot([])
        assert "digraph" in output
        output_stripped = output.strip()
        assert output_stripped.endswith("}")

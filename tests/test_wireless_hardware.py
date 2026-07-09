"""Tests for wireless hardware detection module."""

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── Sample data ──

SAMPLE_IW_LIST_MONITOR = """
Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * AP
\t\t * monitor
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412.0 MHz [1] (30.0 dBm)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5180.0 MHz [36] (23.0 dBm)
\tBand 3:
\t\tFrequencies:
\t\t\t* 5955.0 MHz [1] (23.0 dBm)
"""

SAMPLE_IW_LIST_NO_MONITOR = """
Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * AP
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412.0 MHz [1] (30.0 dBm)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5180.0 MHz [36] (23.0 dBm)
"""

SAMPLE_IW_LIST_2GHZ_ONLY = """
Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * monitor
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412.0 MHz [1] (30.0 dBm)
\t\t\t* 2437.0 MHz [6] (30.0 dBm)
\t\t\t* 2462.0 MHz [11] (30.0 dBm)
"""

SAMPLE_IW_LIST_5GHZ_ONLY = """
Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * monitor
\t\t * AP
\tBand 1:
\t\tFrequencies:
\t\t\t* 5180.0 MHz [36] (23.0 dBm)
\t\t\t* 5200.0 MHz [40] (23.0 dBm)
\t\t\t* 5240.0 MHz [48] (23.0 dBm)
"""

SAMPLE_IW_DEV = """
Interface wlan0
\tifindex 2
\twdev 0x1
\ttype managed
"""

SAMPLE_IW_DEV_MONITOR = """
Interface wlan0mon
\tifindex 3
\twdev 0x2
\ttype monitor
"""

SAMPLE_UEVENT_PCI = """
DRIVER=iwlwifi
PCI_CLASS=28000
PCI_ID=8086:2725
PCI_SUBSYS_ID=8086:0024
PCI_SLOT_NAME=0000:00:14.3
"""

SAMPLE_UEVENT_USB = """
DRIVER=rtl88x2bu
USB_CLASS=ff
USB_ID=0bda:b812
USB_SERIAL=123456
"""


# ── Helper: run function from module ──

def _import_func(func_name):
    """Import a function from wireless_hardware module."""
    import importlib.util
    path = str(PROJECT_ROOT / "scripts" / "wireless_hardware.py")
    spec = importlib.util.spec_from_file_location("wireless_hardware", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load wireless_hardware.py from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, func_name)


class TestParseIwList:
    """Parse supported interface modes from iw list output."""

    def setup_method(self):
        self.parse = _import_func("parse_iw_list_modes")

    def test_detects_monitor_when_present(self):
        modes = self.parse(SAMPLE_IW_LIST_MONITOR)
        assert "monitor" in modes, f"Expected monitor in {modes}"

    def test_detects_managed_when_present(self):
        modes = self.parse(SAMPLE_IW_LIST_MONITOR)
        assert "managed" in modes, f"Expected managed in {modes}"

    def test_does_not_contain_monitor_when_absent(self):
        modes = self.parse(SAMPLE_IW_LIST_NO_MONITOR)
        assert "monitor" not in modes, f"Monitor should not be in {modes}"

    def test_returns_all_modes(self):
        modes = self.parse(SAMPLE_IW_LIST_MONITOR)
        assert len(modes) >= 3, f"Expected at least 3 modes, got {modes}"

    def test_handles_empty_string(self):
        modes = self.parse("")
        assert modes == [], f"Expected empty list for empty string"


class TestParseBands:
    """Parse supported frequency bands from iw list."""

    def setup_method(self):
        self.parse = _import_func("parse_iw_list_bands")

    def test_detects_2ghz(self):
        bands = self.parse(SAMPLE_IW_LIST_MONITOR)
        assert "2.4" in bands, f"Expected 2.4GHz in {bands}"

    def test_detects_5ghz(self):
        bands = self.parse(SAMPLE_IW_LIST_MONITOR)
        assert "5" in bands, f"Expected 5GHz in {bands}"

    def test_detects_6ghz(self):
        bands = self.parse(SAMPLE_IW_LIST_MONITOR)
        assert "6" in bands, f"Expected 6GHz in {bands}"

    def test_2ghz_only(self):
        bands = self.parse(SAMPLE_IW_LIST_2GHZ_ONLY)
        assert "2.4" in bands
        assert "5" not in bands, f"5GHz should not be present: {bands}"
        assert "6" not in bands, f"6GHz should not be present: {bands}"
        assert len(bands) == 1, f"Expected only 1 band: {bands}"

    def test_5ghz_only(self):
        bands = self.parse(SAMPLE_IW_LIST_5GHZ_ONLY)
        assert "5" in bands
        assert "2.4" not in bands
        assert len(bands) == 1, f"Expected only 1 band: {bands}"

    def test_handles_empty_string(self):
        bands = self.parse("")
        assert bands == []


class TestAdapterClassification:
    """Classify adapters as internal vs external USB."""

    def setup_method(self):
        self.classify = _import_func("classify_adapter_from_uevent")

    def test_pci_is_internal(self):
        result = self.classify(SAMPLE_UEVENT_PCI)
        assert result["type"] == "internal", f"PCI should be internal: {result}"
        assert result["bus"] == "pci"
        assert result["driver"] == "iwlwifi"

    def test_usb_is_external(self):
        result = self.classify(SAMPLE_UEVENT_USB)
        assert result["type"] == "external", f"USB should be external: {result}"
        assert result["bus"] == "usb"
        assert result["driver"] == "rtl88x2bu"

    def test_empty_uevent(self):
        result = self.classify("")
        assert result["type"] == "unknown"
        assert result["bus"] == "unknown"

    def test_no_driver(self):
        result = self.classify("PCI_ID=8086:2725\nPCI_SLOT_NAME=0000:00:14.3\n")
        assert result["type"] == "internal"
        assert result["bus"] == "pci"
        assert result["driver"] == ""


class TestBuildInterfaceInfo:
    """Build structured interface info from all sources."""

    def setup_method(self):
        self.build = _import_func("_build_interface_info")

    def test_internal_with_monitor(self):
        info = self.build(
            "wlan0",
            "mt7925e",
            SAMPLE_IW_LIST_MONITOR,
            SAMPLE_UEVENT_PCI,
        )
        assert info["name"] == "wlan0"
        assert info["driver"] == "mt7925e"
        assert info["type"] == "internal"
        assert info["capabilities"]["monitor_mode"] is True
        assert info["capabilities"]["band_2ghz"] is True
        assert info["capabilities"]["band_5ghz"] is True
        assert info["capabilities"]["band_6ghz"] is True

    def test_internal_no_monitor(self):
        info = self.build(
            "wlan0", "iwlwifi",
            SAMPLE_IW_LIST_NO_MONITOR,
            SAMPLE_UEVENT_PCI,
        )
        assert info["capabilities"]["monitor_mode"] is False

    def test_2ghz_only(self):
        info = self.build(
            "wlan0", "iwlwifi",
            SAMPLE_IW_LIST_2GHZ_ONLY,
            SAMPLE_UEVENT_PCI,
        )
        assert info["capabilities"]["band_2ghz"] is True
        assert info["capabilities"]["band_5ghz"] is False
        assert info["capabilities"]["band_6ghz"] is False

    def test_external_usb(self):
        info = self.build(
            "wlan1", "rtl88x2bu",
            SAMPLE_IW_LIST_MONITOR,
            SAMPLE_UEVENT_USB,
        )
        assert info["type"] == "external"
        assert info["bus"] == "usb"
        assert info["capabilities"]["monitor_mode"] is True


class TestFindBestAdapter:
    """Select the best adapter from a list."""

    def setup_method(self):
        self.find = _import_func("find_best_adapter")

    def _make_adapter(self, name, mon=False, usb=False, bands=None):
        return {
            "name": name,
            "driver": "test",
            "type": "external" if usb else "internal",
            "bus": "usb" if usb else "pci",
            "description": f"Test {name}",
            "capabilities": {
                "monitor_mode": mon,
                "packet_injection": mon,
                "band_2ghz": "2.4" in (bands or ["2.4"]),
                "band_5ghz": "5" in (bands or ["5"]),
                "band_6ghz": "6" in (bands or []),
            },
        }

    def test_prefers_external_with_monitor_over_internal(self):
        internal = self._make_adapter("wlan0", mon=False, usb=False)
        external = self._make_adapter("wlan1", mon=True, usb=True)
        best = self.find([internal, external])
        assert best["name"] == "wlan1"

    def test_prefers_monitor_over_no_monitor(self):
        no_mon = self._make_adapter("wlan0", mon=False, usb=False)
        with_mon = self._make_adapter("wlan1", mon=True, usb=False)
        best = self.find([no_mon, with_mon])
        assert best["name"] == "wlan1"

    def test_prefers_external_over_internal_when_both_have_monitor(self):
        internal = self._make_adapter("wlan0", mon=True, usb=False)
        external = self._make_adapter("wlan1", mon=True, usb=True)
        best = self.find([internal, external])
        assert best["name"] == "wlan1"

    def test_falls_back_to_internal_with_monitor(self):
        no_adapter = self._make_adapter("wlan0", mon=False, usb=False)
        with_mon = self._make_adapter("wlan1", mon=True, usb=False)
        best = self.find([no_adapter, with_mon])
        assert best["name"] == "wlan1"

    def test_uses_internal_if_only_one_adapter(self):
        only = self._make_adapter("wlan0", mon=False, usb=False)
        best = self.find([only])
        assert best["name"] == "wlan0"

    def test_returns_none_for_empty_list(self):
        assert self.find([]) is None


class TestRecommendationBanner:
    """Banner text formatting."""

    def setup_method(self):
        self.should_recommend = _import_func("should_show_recommendation")
        self.get_scan_mode = _import_func("get_scan_mode")

    def test_recommends_when_no_monitor(self):
        info = {
            "name": "wlan0",
            "type": "internal",
            "capabilities": {"monitor_mode": False, "packet_injection": False},
        }
        assert self.should_recommend(info) is True

    def test_does_not_recommend_with_monitor(self):
        info = {
            "name": "wlan1",
            "type": "external",
            "capabilities": {"monitor_mode": True, "packet_injection": True},
        }
        assert self.should_recommend(info) is False

    def test_scan_mode_managed_when_no_monitor(self):
        info = {"capabilities": {"monitor_mode": False}}
        assert self.get_scan_mode(info) == "managed"

    def test_scan_mode_full_when_monitor(self):
        info = {"capabilities": {"monitor_mode": True, "packet_injection": True}}
        assert self.get_scan_mode(info) == "full"

    def test_scan_mode_passive_when_monitor_but_no_injection(self):
        info = {"capabilities": {"monitor_mode": True, "packet_injection": False}}
        assert self.get_scan_mode(info) == "passive"


class TestRunIwDevScan:
    """Managed-mode fallback via iw dev scan."""

    def setup_method(self):
        self.parse = _import_func("parse_iw_scan_output")

    SAMPLE_IW_SCAN = """
BSS 00:11:22:33:44:55 (on wlan0)
        SSID: CorpWiFi
        freq: 5180
        signal: -45.00 dBm
        Encryption: WPA2-PSK (CCMP)
BSS AA:BB:CC:DD:EE:FF (on wlan0)
        SSID: GuestNet
        freq: 2437
        signal: -60.00 dBm
        Encryption: WPA2-PSK (CCMP)
BSS 11:22:33:44:55:66 (on wlan0)
        SSID: Office-5G
        freq: 5240
        signal: -52.00 dBm
        Encryption: WPA3-SAE
BSS 99:88:77:66:55:44 (on wlan0)
        (SSID: )
        freq: 2412
        signal: -75.00 dBm
        Encryption: WPA2-PSK (CCMP)
"""

    def test_parses_multiple_aps(self):
        aps = self.parse(self.SAMPLE_IW_SCAN)
        assert len(aps) == 4, f"Expected 4 APs, got {len(aps)}: {aps}"

    def test_parses_ssid(self):
        aps = self.parse(self.SAMPLE_IW_SCAN)
        ssids = [ap["ssid"] for ap in aps]
        assert "CorpWiFi" in ssids
        assert "GuestNet" in ssids
        assert "Office-5G" in ssids

    def test_parses_bssid(self):
        aps = self.parse(self.SAMPLE_IW_SCAN)
        bssids = [ap["bssid"] for ap in aps]
        assert "00:11:22:33:44:55" in bssids

    def test_parses_signal(self):
        aps = self.parse(self.SAMPLE_IW_SCAN)
        signals = {ap["ssid"]: ap["signal_dbm"] for ap in aps}
        assert signals["CorpWiFi"] == -45
        assert signals["GuestNet"] == -60

    def test_parses_encryption(self):
        aps = self.parse(self.SAMPLE_IW_SCAN)
        enc = {ap["ssid"]: ap["encryption"] for ap in aps}
        assert enc["CorpWiFi"] == "WPA2-PSK"
        assert enc["Office-5G"] == "WPA3-SAE"

    def test_parses_hidden_ssid(self):
        aps = self.parse(self.SAMPLE_IW_SCAN)
        hidden = [ap for ap in aps if ap["ssid"] == ""]
        assert len(hidden) == 1
        assert hidden[0]["display_ssid"] == "(hidden)"

    def test_parses_channel_from_freq(self):
        aps = self.parse(self.SAMPLE_IW_SCAN)
        ch = {ap["ssid"]: ap["channel"] for ap in aps}
        # 5180 MHz = channel 36, 2437 MHz = channel 6
        assert ch.get("CorpWiFi") == 36, f"Expected ch 36 for 5180MHz: {ch}"
        assert ch.get("GuestNet") == 6, f"Expected ch 6 for 2437MHz: {ch}"

    def test_handles_empty_scan(self):
        assert self.parse("") == []

    def test_handles_no_bss_section(self):
        assert self.parse("iw dev output\nno BSS lines here\n") == []

# Changelog

All notable changes to PortShim are documented here.

## [v0.5.12] — 2026-07-17

### Added
- `portshim discover` subcommand — automatic VLAN/subnet discovery from the current machine
  - Three depth modes: `--fast` (~2 min), default (~5 min), `--deep` (~10 min)
  - VLAN hunting: probes gateway on adjacent subnet IPs to find all reachable segments
  - Heuristic classification: identifies subnet purpose (Corporate LAN, Infrastructure, Printer, Camera, etc.) from port banners, MAC vendors, hostnames, and HTTP titles
  - JSON output to stdout (pipe-friendly) + human-readable table to stderr
  - `--output file.json` to save the network map
- `vlan-subnet-discovery` Hermes skill — reusable manual workflow for the same task

### Changed
- Landing page Quick Start and README updated with `portshim discover` examples

## [v0.5.11] — 2026-07-14

### Fixed
- Release pipeline: stripped conflicting GitHub Action from public repo (was force-pushing stale HTML over script push, causing version/changelog to never update)
- Release pipeline: changelog regex backreference fixed (`\1` not `\\1`)
- Release pipeline: reminder to commit source version bumps added

### Added
- NIC comparison diagnostic script (`scripts/diag/compare-nics.py`)

### Changed
- Hardware guidance: Dell USB-C (Realtek RTL8153) recommended for wired scanning
- D-Link DUB-1312 (ASIX AX88179) added as tested backup adapter
- Warning added: avoid ASIX adapters on generic cdc_ncm driver
- Warning added: do not scan wired networks over WiFi (ARP broken)
- Warning added: dock Ethernet shares DisplayLink bus — dedicated adapter preferred
- Landing page: requirements + FAQ updated with NIC selection guidance
- Operator guide: quick start and pre-engagement checklist updated

## [v0.5.10] — 2026-07-14

### Fixed
- Release pipeline: version bump source HTML now committed (prevented stale footer/title)
- Release pipeline: changelog regex backreference fixed (`\1` not `\\1`)
- Release pipeline: reminder to commit source version bumps added

### Added
- NIC comparison diagnostic script (`scripts/diag/compare-nics.py`)

### Changed
- Hardware guidance: Dell USB-C (Realtek RTL8153) recommended for wired scanning
- D-Link DUB-1312 (ASIX AX88179) added as tested backup adapter
- Warning added: avoid ASIX adapters on generic cdc_ncm driver
- Warning added: do not scan wired networks over WiFi (ARP broken)
- Warning added: dock Ethernet shares DisplayLink bus — dedicated adapter preferred
- Landing page: requirements + FAQ updated with NIC selection guidance
- Operator guide: quick start and pre-engagement checklist updated

## [v0.5.9] — 2026-07-14

### Added
- NIC comparison diagnostic script (`scripts/diag/compare-nics.py`)

### Changed
- Hardware guidance: Dell USB-C (Realtek RTL8153) recommended for wired scanning
- D-Link DUB-1312 (ASIX AX88179) added as tested backup adapter
- Warning added: avoid ASIX adapters on generic cdc_ncm driver
- Warning added: do not scan wired networks over WiFi (ARP broken)
- Warning added: dock Ethernet shares DisplayLink bus — dedicated adapter preferred
- Landing page: requirements + FAQ updated with NIC selection guidance
- Operator guide: quick start and pre-engagement checklist updated

## [v0.5.8] — 2026-07-13

### Fixed
- Root cause: git init + force push creates orphan commits GitHub
  silently rejects. Now clones public repo and pushes normally.

## [v0.5.7] — 2026-07-13

### Fixed
- Add hard verification of version bump before pushing public repo
- Add debug output to trace bump/push pipeline

## [v0.5.6] — 2026-07-13

### Fixed
- Robust version bump: per-file loop with verification replaces
  fragile find -exec sed that failed silently in release pipeline

## [v0.5.5] — 2026-07-13

### Fixed
- Release script now bumps source portshim-landing/ versions too,
  preventing stale version strings between releases

## [v0.5.4] — 2026-07-13

### Fixed
- report-gen.py: outputs to timestamped subdirectory (wired-{ts}/)
  instead of flat directory — keeps outputs/reports/ clean

## [v0.5.3] — 2026-07-13

### Added
- Changelog page uses full site template (nav, CSS, theme, footer)
- Release guard: rejects release if CHANGELOG.md missing version entry

### Fixed
- Footer Cal-Met link opens in new tab (target="_blank")

## [v0.5.2] — 2026-07-13

### Added
- Auto-generated changelog page on website (pages/changelog.html)
- GitHub Releases auto-created with changelog notes on release
- CHANGELOG.md backfilled from v0.4.0

## [v0.5.1] — 2026-07-13

### Fixed
- Move hashid from system packages to pip (hashid is a Python package, not a system package)

## [v0.5.0] — 2026-07-13

### Added
- masscan, macchanger, john, hashid, exploitdb to deploy.py base install
- Also added missing hcxdumptool, hcxtools, hashcat to deploy.py
- PACKAGE_MAP completeness test to prevent future tool drift

## [v0.4.5] — 2026-07-13

### Fixed
- MAC spoofing: interface left DOWN on failure (added finally block to bring it back up)
- test_report.py: tempfile leak on subprocess failure (fixed cleanup)
- searchsploit: added per-CVE caching to avoid redundant lookups
- Removed dead --force flag from network_scan.py
- Removed unreachable except block in run_john
- Simplified crack_auto dead fallback expression

## [v0.4.4] — 2026-07-13

### Added
- Test report generation: `test_report.py` saves results to `outputs/reports/{wired,wireless}-{timestamp}/`
- Structured JSON + human-readable summary per test run
- Auto-detects wired vs wireless from test file paths

## [v0.4.3] — 2026-07-13

### Added
- searchsploit CVE-to-exploit lookup in `generate-findings.py`
- Findings now include `exploit_available`, `exploit_paths`, `exploit_count`
- john + hashid as alternative cracking backends in `wireless_crack.py`
- `crack_auto()` tries aircrack → hashcat → john in priority order
- MAC spoofing support: `get_current_mac()`, `spoof_mac()`, `restore_mac()`, `random_mac()` in `wireless_hardware.py`
- masscan fast host discovery via `network_scan.py` with nmap fallback

### Fixed
- Double nmap call when masscan fails (Claude review)
- Removed unused `output_format` parameter from `run_masscan`

## [v0.4.2] — 2026-07-13

### Added
- PMKID passive capture via `wireless_pmkid.py` (hcxdumptool → hcxpcapngtool → hashcat)
- Auto-fallback to PMKID capture when airodump-ng returns zero handshakes

### Fixed
- Band suffixes: removed invalid `{ch}b` for 2.4 GHz channels (hcxdumptool convention: a=2.4, b=5, c=6)
- Process timeout: use `timeout --kill-after=5` instead of raw process group kill
- Timestamp correlation between capture and hashcat output files
- Secure output path: write to OUTPUT_DIR instead of /tmp
- Root privilege check before PMKID capture
- Zero-size hcxpcapngtool output detection (no PMKID hashes)
- MT7921AU USB adapter classification via `DEVTYPE=usb_*` fallback
- Landing page version regex: replace ALL vX.Y.Z patterns, not just previous tag

## [v0.4.1] — 2026-07-11

### Fixed
- PDF report: prevent table rows from splitting across pages

## [v0.4.0] — 2026-07-11

### Changed
- Consolidate CVEs per host:port into single findings

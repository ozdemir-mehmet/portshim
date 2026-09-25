# Changelog

All notable changes to PortShim are documented here.

## [v0.5.14] — 2026-09-25

### Added
- Synthetic sample reports on the website. The sample gallery's six images are generated from an invented assessment rather than captured from a real one: `tools/sample-findings.json` holds the fixture (six example findings on the documentation range `192.0.2.0/24`, reserved example hostnames, real public CVE identifiers), `tools/make-sample-report-images.py` renders it through `report-gen.py` and draws a label under every image, and `approved-assets.json` pins the six hashes.
- A release boundary check: `scripts/boundary-check.py`, run against the exported tree before anything is published, failing closed on six conditions — a stripped path referenced by a shipped file, a stripped path present in the tree, a private path written into the copy, a shipped instruction naming something that is not there, a learnings marker, and an asset manifest that does not account for every file in the assets directory. It reads archives and the members inside them, PDF content streams, PNG text chunks and the UTF-16 encodings of all of it; a file it cannot read in full fails the run rather than passing unexamined.
- Agent integration documentation in `references/agent-integration.md`: how to wire PortShim into an agent's own skills and instruction files, with the commands, replacing the installer that used to do it.

### Changed
- The seven pipeline scripts moved to `scripts/` at the repository root, so the tree that holds them is no longer a mix of published code and internal notes.
- `scripts/report-gen.py` takes the assessment date as an input — `--assessment-date`, or `PORTSHIM_REPORT_DATE` — with the month spelled from a fixed table so the output does not depend on the host locale, and a malformed date is an error rather than a silent fallback to today. The target network is read from the findings.
- The `report` extra requires WeasyPrint and `pillow>=10`.
- Shipped documentation re-pointed at paths that exist in the published tree; a page describing a directory as it sits in the development repository now describes the published layout.
- Site copy: a footer credit pointing at an unrelated third party replaced with the product name, and a retired internal placeholder name removed from the pages and the README.
- The landing README's learnings section removed; the guidance it summarised is on the site's own pages and in each tool's `--help`, which is where a reader of the published tree finds it.

### Fixed
- `scripts/render-docs.py` derived its operator-guide directory from a path that does not exist in a published tree and could not be pointed anywhere else. It now takes `--all-guides DIR` and exits with a message when it cannot resolve one.
- The publishing pipeline no longer exports a tree it has not checked. The landing page is read from the committed revision rather than the working copy, so a file no commit has seen cannot ride into a release, and the run refuses to start while any of its own inputs is uncommitted.

## [v0.5.13] — 2026-09-21

### Added
- External tool dependency reference (`references/tool-dependencies.md`) — every tool PortShim shells out to, which pipeline phase uses it, whether it is required or optional, and what stops working when it is absent. The inventory is derived from `deploy.py` so it cannot drift from the installer.
- Dependencies page on the website (`pages/dependencies.html`), linked from the feature grid and from the requirements section.

### Fixed
- `portshim wireless select` and `portshim wireless assess` now honour `--output-dir` for scan discovery, not only for writing results — previously the flag was accepted but discovery always searched `outputs/wireless/`.
- `portshim wireless select` now exposes `--output-dir`, `--auto`, `--max`, `--force` and `--list`. Its forwarding block already read all five, so four were unreachable and `--max` was silently ignored.
- An explicit `--max 0` is honoured instead of being dropped and falling back to 5.

### Changed
- Wireless tests are hermetic: the graceful-failure tests use an isolated output directory, and the association test patches the interface probe rather than requiring a host `wlan0`.
- README System Requirements corrected — the tool list links the new reference, and the Python row no longer implies `requests`, `fpdf2` and `paramiko` are used (no code imports them).
- Executive summary no longer describes subfinder as a Phase 1 recon tool — it is installed but not wired into the pipeline.
- Knowledge sources re-synced (NeuroSploit 4.2.0, nuclei, httpx, nmap-vulners, Anthropic Cybersecurity Skills) and the `nmap/nmap` source dropped — it pointed at a path that does not exist upstream, so it could never sync.
- Website requirements card trimmed to the essentials; Python floor stated as 3.10+ to match `pyproject.toml`.

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
- Release script now bumps the site source versions too,
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
- Footer link opens in new tab (target="_blank")

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

---
title: "PortShim (PortShim)"
subtitle: "On-Site Security Assessment Pipeline"
date: "June 2026"
version: "1.0.0"
classification: "Confidential"
platform: "Linux - Distro-Agnostic"
license: "MIT"
document: "Executive Summary"
---

# Executive Summary

PortShim is a Hermes-orchestrated, distro-agnostic security assessment pipeline that maps a target network, cross-references known CVEs against discovered services, exploits vulnerabilities with IDS-aware stealth profiles, and produces a comprehensive report with an Excel remediation checklist that tracks fixes across retests.

Designed for authorised on-site assessments, PortShim adapts to wired and wireless networks, Windows, Linux, and macOS targets, and operates in three LLM deployment modes: fully local (air-gapped), hybrid (tactical local + strategic cloud), and fully cloud.

| | | |
|---|---|---|
| **Total Components** | **38** | Skills, scripts, tests, references |
| **Pipeline Phases** | **5** | Recon → Vuln → Exploit → Report → Retest |
| **Stealth Profiles** | **3** | Silent Entry, Surgical, Full Assault |

# Pipeline Overview

## Phase 1 — Reconnaissance & Topology

Network discovery via nmap, httpx, subfinder, plus wireless (Kismet/Aircrack-ng). Structured host table with service fingerprinting and optional network topology diagram.

## Phase 2 — Vulnerability Analysis

Cross-references every discovered service version against the NVD via nmap-vulners. Nuclei deep-scans for known CVEs. Guardian Analyst correlates findings with CVSS v3.1 scoring.

## Phase 3 — Exploitation & Access

NeuroSploit (348 agents) and Guardian attack chains execute verified exploits. Anthropic skills cover Linux privilege escalation, Windows lateral movement, cloud exploitation (AWS/Azure/GCP), and Kubernetes penetration testing.

## Phase 4 — Reporting

Generates three deliverables: PowerPoint executive brief, Word technical report with CVSS methodology, and Excel remediation checklist with colour-coded severity and tick columns.

## Phase 5 — Retest & Verification

Compares baseline and retest scans. Auto-classifies findings as FIXED, STILL OPEN, NEW, or REGRESSION. Updates checklist with ticks for resolved items and highlights new findings.

# Architecture

PortShim is built on a five-layer stack with a cross-cutting knowledge-source tracking system that pins every external reference (GitHub repos, NVD feeds, tool docs) to specific commits and detects staleness.

**L5 — Orchestrator**
:   `site-assessment-pipeline` skill drives the full 5-phase flow.

**L4 — Glue Scripts**
:   7 Python scripts: stealth profiles, topology map, report generator (.docx/.pptx/.xlsx), Excel checklist, retest diff, LLM config, deployment bootstrap.

**L3 — Tools**
:   25+ Anthropic cybersecurity skills via npx + Guardian CLI + NeuroSploit + nmap-vulners NSE + nuclei + httpx + subfinder.

**L2 — Skills**
:   Updated guardian-cli, neurosploit-integration, remote-system-access with knowledge-source tracking.

**L1 — Sources**
:   `sources.yaml` per skill + `sync_knowledge.py` + `check-skill-freshness.py`. Commit-pinned references from GitHub repos.

# Built on Open Source

PortShim leverages and extends the following community projects:

| Project | Stars | Role in PortShim |
|---|---|---|
| [Guardian CLI](https://github.com/zakirkun/guardian-cli) | — | Primary scanning engine — 50+ security tools, multi-agent pipeline |
| [NeuroSploit](https://github.com/JoasASantos/NeuroSploit) | — | Autonomous exploitation — 348 agents, cross-model voting, attack chains |
| [nmap-vulners](https://github.com/vulnersCom/nmap-vulners) | 3.3k | CVE cross-referencing — maps service versions to known vulnerabilities |
| [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 23.3k | 25 targeted skills for wireless, privesc, lateral movement, cloud, and reporting |
| [Red Teaming Toolkit](https://github.com/infosecn1nja/red-teaming-toolkit) | — | Curated tool reference organised by kill-chain phase |
| [nmap](https://github.com/nmap/nmap) | — | Network discovery and port scanning |
| [nuclei](https://github.com/projectdiscovery/nuclei) | — | Template-based vulnerability scanning |
| [httpx](https://github.com/projectdiscovery/httpx) | — | HTTP probing and tech stack detection |
| [subfinder](https://github.com/projectdiscovery/subfinder) | — | Subdomain enumeration |
| [Pwndoc](https://github.com/pwndoc/pwndoc) | 2.8k | Pentest report generation (reference) |
| [VECTR](https://github.com/SecurityRiskAdvisors/VECTR) | 1.6k | Red/blue team test tracking (reference) |
| [Vulnreport](https://github.com/salesforce/vulnreport) | 600 | Pentest management and automation (reference) |

PortShim itself — the orchestrator, device classifier, stealth profiles, topology mapper, deployment bootstrap, and knowledge-source tracking — is original work. See `skills/site-assessment-pipeline/sources.yaml` for the complete dependency manifest with commit-pinned tracking.

# End-to-End Example: The Flat Network

*The following is a representative scenario demonstrating what PortShim discovers during a typical on-site assessment of a medium-sized enterprise with a flat network architecture — no VLAN segmentation, no NAC, everything on one subnet.*

## 08:00 — Arrival & Deployment

A single Linux laptop is connected to a wall port in a vacant meeting room. `deploy.py` detects Ubuntu 24.04, installs the full toolkit via `apt`, pulls 25 Anthropic cybersecurity skills, and symlinks PortShim's orchestrator into Hermes. A local GPU runs `hauhauCS-aggressive` for exploitation and `Qwen3-Coder-30B` for reasoning. The engagement begins in **Surgical** mode — fast enough to be thorough, quiet enough to avoid tripping basic IDS.

## 08:04 — Phase 1: Reconnaissance & Device Classification

A `/22` subnet sweep returns 847 live hosts. `topology.py` maps them. `device-classifier.py` immediately flags 23 high-value targets:

| Host | Role | Concern |
|---|---|---|
| 10.0.1.2 | Domain Controller | LDAP on 389 without signing enforcement |
| 10.0.1.10 | Exchange 2016 CU22 | Unpatched — ProxyShell (CVE-2021-34473), ProxyLogon (CVE-2021-26855) |
| 10.0.1.50 | MSSQL Server | Port 1433 exposed to all subnets, xp_cmdshell enabled |
| 10.0.2.5 | Ubiquiti UniFi Controller | v6.2.10 — CVE-2021-44529 (default cred bypass via MongoDB) |
| 10.0.3.100 | Hikvision NVR | Port 554 RTSP streaming without authentication |
| 10.0.4.20 | Hyper-V Host | WinRM on 5985 with NTLM, domain-joined |
| 10.0.5.5 | DPM Server | Port 6075 accepting connections, default service account |

The network has no east-west filtering. Every host can reach every other host. The UniFi controller sits on the same subnet as the domain controller.

## 08:12 — Phase 2: Vulnerability Confirmation

`nmap-vulners` enriches the topology with confirmed CVEs. `nuclei` validates them. The UniFi controller returns `CVE-2021-44529` — an authentication bypass in the bundled MongoDB instance that allows unauthenticated access to the controller's configuration database. The CVE is rated **CVSS 9.8 (Critical)** and has a public proof-of-concept. Guardian's Analyst agent confirms it is remotely exploitable with no prerequisites.

The Hyper-V host shows `CVE-2024-38080` — an elevation of privilege in the Windows Hyper-V Virtualization Service, allowing SYSTEM access on the host from a guest VM.

## 08:18 — Phase 3: Exploitation

NeuroSploit's 348 agents are dispatched against confirmed targets. Within 90 seconds:

1. **UniFi Controller (10.0.2.5)** — The MongoDB bypass yields the controller's `admin` password hash. NeuroSploit cracks it offline (dictionary attack, `hashcat` mode 0). The hash resolves to `admin:unifi2020!` — the controller admin UI is now fully accessible. From the UniFi dashboard: **every managed switch, AP, and client device is visible**, including the SSID PSK for the corporate wireless network and SSH keys for all 47 UniFi APs deployed across the campus.

2. **SSH to APs** — With extracted SSH keys, each AP accepts root login. The APs run a Debian-based UniFi OS. `performing-privilege-escalation-on-linux` identifies that the AP firmware is outdated and vulnerable to `CVE-2024-1086` (`nftables` kernel exploit), yielding root on the AP hardware. From an AP in the server room ceiling, **packet capture reveals cleartext LDAP authentication** between workstations and the domain controller — the domain uses LDAP simple bind without TLS.

3. **Domain Controller (10.0.1.2)** — LDAP without signing or channel binding means NTLM relay is viable. Guardian's `chain_ssrf_to_aws`-style lateral chain adapts: LLMNR poisoning via `Responder` on the attacker laptop captures NTLMv2 hashes from service accounts attempting name resolution. One hash belongs to `SVC_SQL` — a domain account with local admin on the MSSQL server.

4. **MSSQL Server (10.0.1.50)** — `SVC_SQL` authenticates via `impacket-wmiexec`. `xp_cmdshell` is enabled. The MSSQL service account runs as `NT AUTHORITY\SYSTEM`. From here, Mimikatz extracts the domain `KRBTGT` hash from a previous DBA who RDP'd in. **The domain is now owned.**

## 08:27 — Phase 4: Elevated Access Confirmed

With the KRBTGT hash, a Golden Ticket is forged. The attacker has unrestricted access to every domain-joined host — file servers, the Hyper-V cluster, the DPM backup server, every workstation. From the Hyper-V host, all guest VMs are accessible including the PCI cardholder data environment. From DPM, every backup of every critical system is extractable.

**Time from wall jack to domain dominance: 27 minutes.**

No zero-days were used. Every exploit was a publicly known CVE with an available patch. The network's flat architecture meant no lateral movement barriers existed — once one host fell, every host was reachable.

## 08:30 — Phase 5: Report Generated

`report-gen.py` produces a 42-page technical report with CVSS v3.1 severity ratings, step-by-step reproduction evidence, and prioritised remediation steps. `excel-checklist.py` generates a colour-coded tracking workbook. The executive brief highlights the three Critical findings with a recommended 72-hour remediation window.

The assessment demonstrates that in a flat network with unpatched services, a single compromised device — even an IoT-class WiFi controller — can lead to full domain compromise in under 30 minutes.

# Stealth Profiles

Silent Entry
:   IDS-aware, single-thread, 30s probe delay, no brute force, curl-only fingerprinting. *(T1 / -sT)*

Surgical *(default)*
:   Rate-limited SYN, targeted nuclei per discovered service, verified-CVE-only exploitation, common-credential spray only. *(T3 / -sS)*

Full Assault
:   Multi-threaded, full nuclei library, all NeuroSploit agents, complete wordlists, parallel host scanning. *(T5 / -A)*

# LLM Deployment Modes

Fully Local
:   Everything on field laptop GPU. Uncensored local models (hauhauCS, Qwen3-Coder). Air-gap capable with `--offline`.

Hybrid
:   Tactical scanning and exploitation stay local. Strategic planning and reports use cloud API.

Fully Cloud
:   Thin client runs CLI tools only. All LLM work via API. Scan results uploaded to Hermes instance.

# Testing Strategy

PortShim ships with 155 unit tests across 8 test modules and 3 integration test modules. All unit tests run offline with mocked network calls. Integration tests include a knowledge-sync live test (GitHub API), a pipeline smoke test against `scanme.nmap.org`, and a skill-consistency test verifying all `sources.yaml` references are current within 30 days.

# Deliverables

| Deliverable | Format | Description |
|---|---|---|
| Executive Brief | `.pptx` | High-level findings, risk summary, recommended actions |
| Technical Report | `.docx` | Full finding details, CVSS vectors, remediation steps, methodology appendix |
| Remediation Checklist | `.xlsx` | Colour-coded severity, tick column, retest date tracking, summary dashboard |
| Network Topology | `.dot` / table | Structured host table with CVE annotations. Optional graphviz network diagram |
| Retest Delta Report | `.docx` / `.xlsx` | Before/after comparison. Auto-classified: FIXED, STILL OPEN, NEW, REGRESSION |

# Deployment

A single bootstrap script (`deploy.py`) detects the target Linux distribution by probing `/etc/*-release` files and selects the correct package manager (apt, dnf, pacman, zypper, or apk). It installs system packages, Go-based security tools (nuclei, httpx, subfinder), Python dependencies, and the Anthropic cybersecurity skill library via npx — all in one command. No hardcoded package managers. No assumptions about the target environment.

# Key Metrics

| Metric | Value |
|---|---|
| Total Components | 38 files (skills, scripts, tests, references) |
| Custom Code | ~380 lines Python (7 glue scripts) |
| Existing Tools | Guardian CLI (50+ tools), NeuroSploit (348 agents), Anthropic (25+ skills), nmap-vulners |
| Stealth Profiles | 3 (Silent Entry, Surgical, Full Assault) |
| LLM Modes | 3 (Local, Hybrid, Cloud) |
| Report Formats | 5 (.pptx, .docx, .xlsx, .dot, plain table) |
| Target Platforms | Wired + wireless, Windows + Linux + macOS + cloud + OT/ICS |
| Unit Tests | 155 passing across 8 modules |
| Integration Tests | 3 modules (knowledge-sync live, pipeline smoke, skill consistency) |

---

**PortShim is ready for authorised deployment.**

Run `deploy.py` on the target Linux machine to bootstrap the full capability.

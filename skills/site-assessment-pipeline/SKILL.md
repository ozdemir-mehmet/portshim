---
name: site-assessment-pipeline
description: Full-site security assessment pipeline — recon, vulnerability mapping, exploitation, reporting, and remediation tracking with IDS-aware stealth profiles and operator review gates between every phase. Use when targeting a network or site for authorized security assessment.
version: 2.0.0
author: PortShim
license: MIT
metadata:
  hermes:
    tags: [security, pentesting, red-team, assessment, pipeline, portshim]
    related_skills: [guardian-cli, neurosploit-integration, remote-system-access]
---

# Site Assessment Pipeline

PortShim's master orchestrator — a six-phase security assessment pipeline with operator review gates between every phase.

**Key rule:** Every phase ends with a review gate. Do NOT proceed to the next phase until the operator explicitly approves.

## Engagement Summary

```
Phase 0: SETUP    → Bootstrap, sync, configure
    ↓  [GATE 0: Confirm scope, stealth, LLM mode]
Phase 1: RECON    → Discover hosts, classify devices, map topology
    ↓  [GATE 1: Review network map, adjust scope, rerun if needed]
Phase 2: VULN     → Cross-reference CVEs, CVSS scoring, prioritize
    ↓  [GATE 2: Review findings, select exploitation targets]
Phase 3: EXPLOIT  → Verify exploitable, escalate, move laterally
    ↓  [GATE 3: Review exploitation evidence, redact if needed]
Phase 4: REPORT   → Generate .docx, .pptx, .xlsx deliverables
    ↓  [GATE 4: Review reports, approve for client delivery]
Phase 5: RETEST   → Rescan, classify fixes, update checklist
    ↓  [GATE 5: Final sign-off]
```

## Quick Start

```bash
# 1. Choose your deployment mode
python scripts/llm-config.py local --output-dir ./configs/

# 2. Choose your stealth profile
python scripts/stealth-profiles.py surgical

# 3. Before each engagement — sync knowledge
python scripts/sync_knowledge.py --all
python scripts/check-skill-freshness.py

# 4. Load this skill in Hermes
/skill site-assessment-pipeline
```

## Review Gate Protocol

At every gate, Hermes presents the phase output to the operator and asks:

| Decision | Meaning | Result |
|---|---|---|
| **APPROVE** | Output is correct. Proceed. | Advance to next phase. |
| **RERUN** | Something missed or wrong. Repeat with changes. | Rerun the same phase with operator-provided adjustments (different flags, wider subnet, different profile, etc.) |
| **MODIFY SCOPE** | Scope needs to change. | Adjust target range, stealth profile, add/remove wireless, change LLM mode, then rerun phase. |
| **ABORT** | Stop the engagement. | Halt entire pipeline. Save all outputs so far. |

Hermes must use the `clarify` tool at every gate — do not assume approval.

---

## Phase 0: Pre-Engagement Setup

**Goal:** Bootstrap the environment, sync knowledge, configure for this specific engagement.

| Step | Command | Notes |
|---|---|---|
| 0.1 Bootstrap | `python deploy.py` | Distro-aware — installs nmap, nuclei, Go tools, Python deps, Anthropic skills |
| 0.2 Sync knowledge | `python scripts/sync_knowledge.py --all` | Pull latest from 7 tracked GitHub repos |
| 0.3 Freshness check | `python scripts/check-skill-freshness.py` | Warn if any tracked repo >30 days stale |
| 0.4 Choose LLM mode | `python scripts/llm-config.py <local\|hybrid\|cloud>` | Air-gap / field / thin-client |
| 0.5 Choose stealth | `python scripts/stealth-profiles.py <silent-entry\|surgical\|full-assault>` | IDS-aware timing, thread count, aggressiveness |
| 0.6 Load orchestrator | `/skill site-assessment-pipeline` | Hermes now drives the pipeline |

**Output:** Configured environment, fresh knowledge, selected profile + LLM mode.

### 🔴 Gate 0 — Engagement Confirmation

**Hermes must present to operator:**
- Target IP range / CIDR
- Stealth profile selected
- LLM deployment mode
- Wireless in scope? (yes/no)
- Any known exclusions?

**Operator may:** Adjust CIDR, change profile, add/remove wireless, change LLM mode, provide exclusion list.

---

## Phase 1: Reconnaissance & Topology

**Goal:** Discover every live host, classify device roles, map the network, flag high-risk targets.

| Step | Command |
|---|---|
| 1.1 Ping sweep | `nmap -sT -T4 --open -p 22,80,443,445,3389,8080,8443 <target>/24` |
| 1.2 Service probe | `httpx -l live_hosts.txt -tech-detect -status-code -title` |
| 1.3 Wireless pre-flight | Run hardware capability check (see below). Skip to 1.5 if wireless not in scope. |
| 1.4 Wireless scan | Anthropic skill: `conducting-wireless-network-penetration-test` — only if pre-flight passed |
| 1.5 Parse → JSON | `python scripts/topology.py scan.xml --json > topology.json` |
| 1.6 Classify devices | `python scripts/device-classifier.py topology.json` |
| 1.7 Flag high-risk | `python scripts/device-classifier.py topology.json --findings` |
| 1.8 Generate diagram | `python scripts/topology.py scan.xml --dot > topology.dot` |

#### Step 1.3 — Wireless Hardware Pre-Flight Check

Before running any wireless scanning, Hermes must discover available adapters and test their capabilities. **Always test every adapter found — external first, then internal.** Run whatever is possible with whatever hardware is present.

```bash
# 1. Discover all Wi-Fi adapters
echo "=== External adapters ==="
lsusb | grep -iE 'alfa|realtek|ralink|atheros|mediatek|rtl|mt76' || echo "(none found)"
echo "=== Internal adapters ==="
lspci | grep -iE 'network|wireless|wifi|802\.11' || echo "(none found)"

# 2. List all wireless interfaces and their capabilities
for iface in $(iw dev 2>/dev/null | grep Interface | awk '{print $2}'); do
    echo "--- $iface ---"
    iw list 2>/dev/null | grep -A1 "monitor" | head -1 && echo "  MONITOR: supported" || echo "  MONITOR: unsupported"
done

# 3. For the best available adapter, test monitor mode and injection
#    (prefer external; fall back to internal)
airmon-ng start wlan0 2>&1
aireplay-ng --test wlan0mon 2>&1 | grep -q "Injection is working" && echo "INJECTION_OK" || echo "INJECTION_FAIL"
```

**Decision matrix — run whatever the hardware can do:**

| Adapter | Monitor | Injection | Action | Finding |
|---|---|---|---|---|
| External | ✅ | ✅ | Full wireless pentest (Step 1.4) | — |
| External | ✅ | ❌ | Kismet passive + skip active attacks | `WIRELESS-INJECTION-LIMITED` |
| External | ❌ | ❌ | Kismet passive (attempt only — may fail) | `WIRELESS-HARDWARE-MISSING` |
| Internal only | ✅ | ❌ | Kismet passive + skip active attacks | `WIRELESS-HARDWARE-MISSING` |
| Internal only | ❌ | ❌ | Attempt Kismet (likely fails — record result) | `WIRELESS-HARDWARE-MISSING` |
| Nothing found | — | — | Nothing possible — record finding | `WIRELESS-HARDWARE-MISSING` |

**Key principle:** Never skip wireless entirely without trying. Always run the Kismet passive assessment skill (`performing-wireless-security-assessment-with-kismet`) if monitor mode is available on *any* adapter, even internal. If no monitor mode exists, attempt it anyway and record the failure. The goal is maximum coverage with available hardware, with every limitation documented.

**If full capabilities are unavailable, Hermes must record a finding:**

```json
{
  "id": "WIRELESS-HARDWARE-MISSING",
  "severity": "LIMITATION",
  "title": "Wireless Assessment Partial — External Wi-Fi Hardware Recommended",
  "description": "No external Wi-Fi adapter with packet injection capability was detected. The assessment was performed using the internal [ADAPTER_NAME] adapter which [SUPPORTS/DOES NOT SUPPORT] monitor mode. Active wireless attacks (deauthentication, WPA handshake capture, evil twin AP deployment, PMKID capture, WPA3 downgrade) were skipped. Passive RF monitoring via Kismet was [PERFORMED/ATTEMPTED] to detect rogue APs, hidden SSIDs, and weak encryption configurations.",
  "recommendation": "For a complete wireless penetration test including active attacks, re-run Phase 1.3 with an external USB Wi-Fi adapter that supports monitor mode and packet injection. Recommended: Alfa AWUS036ACH (Realtek RTL8812AU). Connect the adapter and verify with: airmon-ng start wlan0 && aireplay-ng --test wlan0mon"
}
```

**If injection is unavailable but monitor mode works (partial capability):**

```json
{
  "id": "WIRELESS-INJECTION-LIMITED",
  "severity": "LIMITATION",
  "title": "Wireless Assessment Partial — Packet Injection Unavailable",
  "description": "The [ADAPTER_NAME] adapter supports monitor mode but does not support packet injection. The following active attacks were skipped: deauthentication, WPA handshake capture, evil twin AP deployment, PMKID capture, and WPA3 downgrade attacks. Passive monitoring via Kismet was performed to detect rogue APs, hidden SSIDs, and weak encryption.",
  "recommendation": "For full wireless penetration testing including active attacks, use an injection-capable adapter (Alfa AWUS036ACH)."
}
```

**Hermes must substitute `[ADAPTER_NAME]`, `[SUPPORTS/DOES NOT SUPPORT]`, and `[PERFORMED/ATTEMPTED]` with the actual hardware name and test results.**

These findings must appear in the final report deliverables alongside all other findings.

**Output:** `topology.json`, `topology.dot`, `live_hosts.txt`, device classification + high-risk flag list, wireless pre-flight result (and wireless findings if any).

### 🔴 Gate 1 — Reconnaissance Review

**Hermes must present to operator:**
- Total live hosts discovered
- Device classification breakdown (Domain Controllers, IoT, NVRs, servers, workstations, etc.)
- High-risk flagged hosts list
- Topology diagram or summary table
- **Wireless pre-flight result** (FULL / PASSIVE-ONLY / ATTEMPTED / NONE — with adapter name and finding ID)

**Operator may:**
- **APPROVE** → proceed to Phase 2
- **RERUN** → repeat with changes (wider CIDR, add `-p-` for all ports, adjust timing, deeper scan on a specific subnet)
- **MODIFY SCOPE** → expand/shrink target range, adjust stealth, add wireless
- **ABORT** → stop engagement

---

## Phase 2: Vulnerability Analysis

**Goal:** Cross-reference every discovered service version against known CVEs, score by CVSS v3.1, prioritize.

| Step | Command |
|---|---|
| 2.1 CVE cross-reference | `nmap -sV --script vulners <target>` |
| 2.2 Deep template scan | `nuclei -l live_hosts.txt -severity critical,high,medium` |
| 2.3 Guardian analysis | `python -m cli.main workflow run --name recon --target <target>` |
| 2.4 CVSS scoring | Anthropic skill: `prioritizing-vulnerabilities-with-cvss-scoring` |
| 2.5 Enrich topology | `python scripts/topology.py scan.xml --enrich cves.json` |

**Output:** `findings.json`, `cves.json` — CVSS-scored, sorted Critical → High → Medium.

### 🔴 Gate 2 — Findings Review & Exploitation Target Selection

**Hermes must present to operator:**
- Finding summary: Critical (CVSS 9.0+) / High (7.0–8.9) / Medium (4.0–6.9) counts
- Top 10 findings with host, CVE, CVSS, and short description
- Full `findings.json` available for deep inspection

**Operator decides:**
- **Which hosts to exploit** — explicit target list (e.g., "10.0.1.2, 10.0.1.50, 10.0.2.5")
- **Which findings to skip** — false positives, out-of-scope, or accept-risk items
- **Exploitation priority order**

**Operator may:**
- **APPROVE** (with target list) → proceed to Phase 3 — only approved targets exploited
- **RERUN** → deeper scan on specific hosts, add ports, different nuclei templates
- **MODIFY SCOPE** → adjust target list, change stealth (e.g., go Surgical for a deeper look at one subnet)
- **ABORT** → stop engagement

**⚠️ CRITICAL: Phase 3 will ONLY exploit hosts explicitly approved by the operator at this gate.**

---

## Phase 3: Exploitation & Access

**Goal:** Exploit confirmed CVEs on approved targets. Escalate privileges. Move laterally. Capture evidence.

**Preconditions:** Operator must have approved specific target hosts at Gate 2.

| Step | Command | Target |
|---|---|---|
| 3.1 Autonomous exploit | `neurosploit run <target> --vote-n 1 --report-format json` | Approved target list |
| 3.2 Attack chains | `python -m cli.main workflow run --name web_pentest --target <target>` | Approved web targets |
| 3.3 Linux privesc | Anthropic skill: `performing-privilege-escalation-on-linux` | Compromised Linux hosts |
| 3.4 Windows lateral | Anthropic skill: `performing-lateral-movement-with-wmiexec` | Compromised Windows hosts |
| 3.5 Cloud targets | Anthropic skill: `performing-cloud-penetration-testing-with-pacu` (AWS/GCP) | If cloud in scope |

**Output:** Exploitation evidence (screenshots, hashes, extracted creds, lateral movement paths) appended to `findings.json`.

### 🔴 Gate 3 — Exploitation Evidence Review

**Hermes must present to operator:**
- Which targets were successfully exploited (with evidence)
- Which targets were NOT exploitable (with reason — patched, not reachable, credential required, etc.)
- Privilege escalation paths discovered
- Any lateral movement chains established
- Any OPSEC concerns (IDS alerts triggered, accounts locked, logs generated)

**Operator may:**
- **APPROVE** → evidence accepted, proceed to Phase 4
- **RERUN** → retry specific targets with different approach, different exploit, different timing
- **REDACT** → remove specific findings from report output (e.g., sensitive internal hostnames, hash values, PII from captured traffic)
- **MODIFY SCOPE** → if lateral movement revealed new subnets/hosts, add them to scope and return to Phase 1
- **ABORT** → stop engagement, save all evidence

---

## Phase 4: Reporting

**Goal:** Generate client deliverables from reviewed, approved findings.

| Step | Command |
|---|---|
| 4.1 Technical report | `python scripts/report-gen.py findings.json --format docx` |
| 4.2 Executive brief | `python scripts/report-gen.py findings.json --format pptx` |
| 4.3 Remediation checklist | `python scripts/excel-checklist.py findings.json --output checklist.xlsx` |

**Output:** `reports/portshim-report-YYYYMMDD.docx`, `.pptx`, `checklist.xlsx`.

### 🔴 Gate 4 — Report Review & Delivery Approval

**Hermes must present to operator:**
- Report summary: finding count, severity breakdown, key recommendations
- Paths to generated files

**Operator may:**
- **APPROVE** → reports are client-ready, deliver
- **RERUN** → regenerate with adjustments (different template, add/remove sections, fix formatting)
- **REDACT** → remove or mask specific content across all deliverables
- **ABORT** → hold reports, do not deliver

---

## Phase 5: Retest & Verification

**Goal:** After client remediates — rescan, classify fixes, update checklist.

| Step | Command |
|---|---|
| 5.1 Rescan | Re-run Phases 1+2 against same target range |
| 5.2 Compare | `python scripts/retest-diff.py baseline.json retest.json` |
| 5.3 Update checklist | `python scripts/retest-diff.py baseline.json retest.json --update checklist.xlsx` |
| 5.4 Delta report | `python scripts/report-gen.py retest-findings.json --format docx --prefix retest` |

**Output:** Updated checklist with FIXED / STILL OPEN / NEW / REGRESSION classifications, delta `.docx`.

### 🔴 Gate 5 — Retest Sign-Off

**Hermes must present to operator:**
- Fix rate: how many findings are now FIXED vs STILL OPEN
- Any NEW findings from the rescan
- Any REGRESSIONs (previously fixed, now broken again)

**Operator may:**
- **APPROVE** → engagement complete, archive
- **RERUN** → if client claims fixes that didn't verify, rerun specific checks
- **ABORT** → engagement paused, send STILL OPEN findings back to client

---

## Stealth Profiles

| Profile | Use When | Key Behavior |
|---|---|---|
| **Silent Entry** | IDS/IPS present | Single-thread, 30s delays, no brute force, curl-only |
| **Surgical** (default) | Balanced assessment | Rate-limited SYN, targeted nuclei, verified-CVE-only |
| **Full Assault** | Time-critical, full coverage | Multi-threaded, all agents, complete wordlists |

Select: `python scripts/stealth-profiles.py <profile>`

## LLM Deployment Modes

| Mode | Local Models | Cloud | Best For |
|---|---|---|---|
| **Local** | Qwen3-Coder, SuperGemma4 | None | Air-gapped sites |
| **Hybrid** | Qwen3-Coder (exploit), SuperGemma4 (report) | DeepSeek (reports) | Field laptop |
| **Cloud** | None (tools only) | DeepSeek (everything) | Thin client, no GPU |

Configure: `python scripts/llm-config.py <mode> --output-dir ./configs/`

### Per-Phase Model Selection

Based on benchmark results at `references/benchmarks/llm-model-matrix.md`:

| Phase | Best Local Model | Best Cloud Model | Notes |
|---|---|---|---|
| **1. Recon** | Qwen3-Coder 30B (17.8 GB) | DeepSeek V4 | Any model works. Parsing is trivial. |
| **2. Vuln Analysis** | Qwen3-Coder 30B (17.8 GB) | DeepSeek V4 | Cloud preferred for current CVE knowledge. |
| **3. Exploit** | SuperGemma4 26B (16 GB) | ⚠️ DeepSeek refuses specifics | Cloud models refuse exploit commands. Use local uncensored. |
| **4. Report** | SuperGemma4 26B (16 GB) | DeepSeek V4 | DeepSeek best narrative. SuperGemma4 best local. |

> **Key finding:** HauhauCS 35B scored PARTIAL on exploit reasoning despite "uncensored" label. Qwen3-Coder and SuperGemma4 outperformed it. Smaller architecture > larger parameters.

### Model Path Configuration

Set the models directory before running:
```bash
export PD_MODELS_DIR=/opt/models  # Or C:/LocalModels on Windows
```

The path is configurable per installation — never hardcoded.

## Scan History Database

Findings from every engagement are automatically saved to a SQLite database for cross-engagement analytics.

```bash
# Query all engagements
python scripts/query-db.py --engagements

# Find all critical findings across engagements
python scripts/query-db.py --severity critical

# Compare two engagements
python scripts/query-db.py --compare acme-june acme-july

# Aggregate stats
python scripts/query-db.py --stats

# Manually save findings
python scripts/save-to-db.py findings.json --engagement acme-july

# Import legacy JSON data
python scripts/import-legacy.py findings.json --engagement old-scan
```

**Auto-save:** Phase 4 (report generation) and Phase 5 (retest) automatically write to the database. No extra steps needed.

**Config:** Database path via `PD_DB_PATH` env var. Default: `~/.portshim/scan-history.db`

## Key Scripts

| Script | Purpose |
|---|---|
| `scripts/stealth-profiles.py` | IDS-aware tool flags per profile |
| `scripts/topology.py` | nmap XML → host table + DOT diagram |
| `scripts/device-classifier.py` | Classify hosts by device role (40+ types) |
| `scripts/report-gen.py` | findings → .docx + .pptx |
| `scripts/excel-checklist.py` | findings → .xlsx with ticks |
| `scripts/retest-diff.py` | baseline vs retest classifier |
| `scripts/llm-config.py` | per-mode tool config generator |
| `../scripts/sync_knowledge.py` | GitHub → references/ sync |
| `../scripts/check-skill-freshness.py` | staleness detection |
| `../../deploy.py` | distro-aware full bootstrap |

## Knowledge Sources

This skill tracks 7 external repositories. Before each engagement, sync:

```bash
python scripts/sync_knowledge.py --skill site-assessment-pipeline
```

See `sources.yaml` for the full list and pinning details.

## Pitfalls

| Pitfall | Fix |
|---|---|
| nmap SYN scan needs root/raw sockets | Use `-sT` (TCP connect) if not root |
| Nuclei needs updated templates | Run `nuclei -update-templates` first |
| Guardian path issues | Ensure `~/go/bin` and `~/.hermes/tools/bin` are in PATH |
| Cloud models refuse exploits | Use local uncensored model (hauhauCS) in local/hybrid modes |
| nmap-vulners needs API key | Set `VULNERS_API_KEY` env var or use free tier |
| Excel generation fails | Install: `pip install openpyxl python-docx python-pptx` |
| Phases run without operator review | Hermes MUST use `clarify` tool at every gate — never auto-advance |
| Wireless phase fails silently | Internal Wi-Fi cards lack monitor mode + injection. Pre-flight check (Step 1.3) catches this and records finding `WIRELESS-HARDWARE-MISSING`. For full wireless pentest, connect an Alfa AWUS036ACH. |

## Deliverables

| Format | Content | Script |
|---|---|---|
| `.docx` | Technical report with CVSS, findings, remediation | `report-gen.py` |
| `.pptx` | Executive brief with charts | `report-gen.py` |
| `.xlsx` | Color-coded checklist with tick columns | `excel-checklist.py` |
| `.dot` | Network topology diagram (graphviz) | `topology.py --dot` |
| `table` | Terminal-readable host table | `topology.py` |

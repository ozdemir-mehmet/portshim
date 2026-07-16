# Operator's Quick Start

> You have a target. You have authorisation. Here's how to run PortShim.

## What You Need

| Item | Requirement |
|---|---|
| Laptop | Linux (Ubuntu 22.04+, Fedora 38+, Debian 12+, etc.) |
| Authorisation | Signed letter specifying target IP range, SSIDs (if wireless), testing window |
| Target info | IP range (e.g., `10.0.0.0/22`), any known exclusions |
| Internet | Required for `deploy.py` and `sync_knowledge.py` (not needed after setup for local mode) |
| External Wi-Fi adapter | **Only if wireless testing is in scope.** Alfa AWUS036ACH recommended. Pre-flight check will tell you if it's missing. |
| Wired Ethernet | **Direct wired connection required** — do not scan over WiFi. Use a USB-to-Ethernet adapter if no native RJ45 port. Dell USB-C (Realtek RTL8153) recommended. See pre-engagement checklist for details. |

## Step 1: Deploy

On the Linux laptop connected to the target network:

```bash
git clone https://github.com/ozdemir-mehmet/portshim.git
cd portshim
python deploy.py
```

This installs nmap, nuclei, httpx, subfinder, Python dependencies, and 25 Anthropic cybersecurity skills. One command.

## Step 2: Sync Knowledge

Pull the latest CVE data, exploit signatures, and skill updates:

```bash
python scripts/sync_knowledge.py --all
python scripts/check-skill-freshness.py
```

Do this before every engagement. Takes ~30 seconds.

## Step 3: Configure for This Engagement

Pick your stealth profile and LLM mode:

```bash
# Stealth: silent-entry | surgical | full-assault
python skills/site-assessment-pipeline/scripts/stealth-profiles.py surgical

# LLM mode: local | hybrid | cloud
python skills/site-assessment-pipeline/scripts/llm-config.py hybrid
```

| If you're... | Use stealth | Use LLM mode |
|---|---|---|
| On a sensitive network with IDS | `silent-entry` | `local` (air-gap) |
| Default assessment | `surgical` | `hybrid` |
| In a hurry, full coverage needed | `full-assault` | `cloud` |

## Step 4: Load the Pipeline

In Hermes:

```
/skill site-assessment-pipeline
```

Hermes is now the operator. It will walk you through the phases.

## Step 5: Start the Engagement

Tell Hermes your target. For example:

> "Start Phase 0. Target is 10.0.0.0/22. Wireless in scope? No. Use the current config."

Hermes will:

1. Confirm scope at **Gate 0** (you approve or adjust)
2. Run **Phase 1: Reconnaissance** — discovers every host, classifies devices
3. Show results at **Gate 1** (you review, can rerun with different scope)
4. Run **Phase 2: Vulnerability Analysis** — maps CVEs to services
5. Show findings at **Gate 2** (you pick which targets to exploit)
6. Run **Phase 3: Exploitation** — verifies exploits on approved targets
7. Show evidence at **Gate 3** (you review, redact if needed)
8. Generate **Phase 4: Reports** — .docx, .pptx, .xlsx
9. Show reports at **Gate 4** (you approve before client delivery)

## What You Do at Each Gate

At every gate, Hermes will present a summary and ask what to do. Your options:

| Option | When to use |
|---|---|
| **APPROVE** | Output looks correct. Proceed. |
| **RERUN** | Something's off. "Rerun with `-p-` for all ports" or "Rescan that subnet with Surgical instead" |
| **MODIFY SCOPE** | The target range is wrong, or you need to add wireless, or change stealth |
| **ABORT** | Stop immediately. Save everything. |

You cannot auto-advance. Hermes will wait for you.

## What You Get

After Phase 4, in the `reports/` directory:

| File | What it is | Who reads it |
|---|---|---|
| `portshim-report-YYYYMMDD.docx` | Technical report — every finding with CVSS, evidence, remediation | Engineers, security team |
| `portshim-brief-YYYYMMDD.pptx` | Executive brief — risk summary, top findings, recommended actions | CISO, management |
| `checklist.xlsx` | Colour-coded tracking spreadsheet with tick columns | Project manager, remediation owner |

## Retesting (Phase 5)

After the client fixes things, re-run:

```
/skill site-assessment-pipeline
```

Select Phase 5. Hermes rescans, compares to baseline, and classifies every finding as:

- **FIXED** — remediated successfully
- **STILL OPEN** — not fixed
- **NEW** — new vulnerability since baseline
- **REGRESSION** — was fixed, now broken again

The checklist updates automatically with ticks and retest dates.

## Wireless Testing?

If wireless is in scope, Phase 1.3 runs a pre-flight check. If the Alfa card is connected, you get a full wireless pentest (evil twin, WPA handshake capture, WPA3 downgrade). If only the internal adapter is available, Kismet passive monitoring runs and the limitation is documented in the report.

## Stuck?

- "No hosts found?" → Check your IP range. Try `ping <gateway>` first.
- "nmap needs root?" → It does for SYN scans. `deploy.py` handles this.
- "Wireless pre-flight failed?" → The report will say why. Get the Alfa card and re-run.
- "Report won't generate?" → `pip install openpyxl python-docx python-pptx`

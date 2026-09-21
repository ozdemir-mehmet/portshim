# Phase-by-Phase Decision Guide

> What you see at each gate, what it means, and what to decide.

## How This Guide Works

Each section covers one gate. For each gate you'll see:

- **What Hermes shows you** — a sample of the output
- **What to look for** — the key things to check before approving
- **When to RERUN** — common reasons to repeat the phase
- **When to MODIFY SCOPE** — common reasons to change targets or settings

---

## Gate 0 — Engagement Confirmation

**When:** After setup, before scanning begins.

### What Hermes Shows

```
Target: 10.0.0.0/22
Stealth: Surgical
LLM mode: Hybrid
Wireless in scope: No
Exclusions: (none provided)
Proceed?
```

### What to Check

- [ ] IP range is correct (wrong subnet = scan the wrong network)
- [ ] Stealth profile matches the environment (IDS present? Use Silent Entry)
- [ ] Wireless is correctly toggled (it defaults to "no" — make sure you didn't forget)
- [ ] Any known exclusions are listed (printers? VoIP phones? OT/ICS gear?)

### When to RERUN

N/A — this is a config check, not a scan. Just adjust values and approve.

### When to MODIFY SCOPE

- "Actually, the /22 is wrong. Should be /24."
- "Wireless should be in scope — there's a corporate Wi-Fi network."
- "Switch to Silent Entry — they mentioned IDS in the pre-engagement call."

---

## Gate 1 — Reconnaissance Review

**When:** After nmap + httpx + device classification.

### What Hermes Shows

```
Live hosts: 847
Device breakdown:
  Workstations: 612
  Servers: 89
  Network devices: 47
  IoT/Embedded: 23
  Domain Controllers: 3
  Unknown: 73

High-risk flagged: 23 hosts
  - 10.0.1.2   (Domain Controller, LDAP without signing)
  - 10.0.1.10  (Exchange 2016, unpatched)
  - 10.0.1.50  (MSSQL, xp_cmdshell enabled)
  - ...

Topology diagram: topology.dot
```

### What to Look For

- **Host count makes sense** — 847 hosts on a /22 is plausible. 3 hosts on a corporate /16 probably means something's wrong (VLAN isolation, firewall blocking, wrong subnet).
- **Device roles are sane** — if every host is "Unknown," your fingerprinting is too passive. Try Surgical or Full Assault.
- **High-risk hosts make sense** — a Domain Controller flagged for LDAP signing is normal. A printer flagged as Critical is probably a false positive (check in Phase 2).
- **Wireless result** — if you asked for wireless, check the pre-flight result. FULL = good. PASSIVE-ONLY = limited. ATTEMPTED = failed. NONE = no adapter found.

### When to RERUN

- Too many "Unknown" devices → switch to Full Assault or add `-p-` for all ports
- Host count too low → check if the subnet is larger than you thought, or if a firewall is blocking
- Wireless pre-flight failed → connect the Alfa card and re-run

### When to MODIFY SCOPE

- "We missed a subnet." Add it.
- "Wireless needs to be added." Enable it.
- "This is too noisy." Switch to Silent Entry.

---

## Gate 2 — Findings Review & Target Selection

**When:** After CVE cross-referencing and CVSS scoring. **This is the most important gate.**

### What Hermes Shows

```
Findings by severity:
  Critical (9.0+): 12
  High (7.0-8.9):   34
  Medium (4.0-6.9): 89

Top findings:
  #1  10.0.2.5   UniFi Controller v6.2.10   CVE-2021-44529   CVSS 9.8   CRITICAL
       Auth bypass via MongoDB. Public PoC available. Remotely exploitable.

  #2  10.0.1.10  Exchange 2016 CU22         CVE-2021-34473   CVSS 9.8   CRITICAL
       ProxyShell. Pre-auth RCE. Public exploit.

  #3  10.0.1.2   Windows Server 2019 DC     LDAP Signing Off  CVSS 7.5   HIGH
       NTLM relay possible. No channel binding.

  (full findings.json available for inspection)

Which hosts should Phase 3 exploit?
```

### What to Look For

- **False positives** — a "Critical" CVE on a printer usually means the version string matched but the vulnerability doesn't actually apply. Flag these for skip.
- **Public PoC / exploit available** — findings that say "exploit available" are high-confidence. Findings without a known exploit are lower priority.
- **CVSS score + context** — a CVSS 9.8 on an internet-facing Exchange server is emergency-level. The same CVE on an internal-only dev server is still bad but less urgent.
- **Out-of-scope systems** — if a finding is on a host not in your authorisation, exclude it.

### What You Decide Here

**You must provide an explicit target list.** Hermes will ONLY exploit hosts you approve. Example:

> "Exploit: 10.0.2.5, 10.0.1.10, 10.0.1.2, 10.0.1.50. Skip 10.0.5.100 (out of scope)."

### When to RERUN

- "Run nuclei with more templates on the web servers."
- "Rescan 10.0.2.0/24 with all ports — the UniFi controller might have more exposed."
- "I need the full service version on that unknown device before deciding."

### When to MODIFY SCOPE

- "Add 10.0.10.0/24 — the DC has trusts to another domain there."
- "Switch to Surgical for a deeper look at just the server subnet."

---

## Gate 3 — Exploitation Evidence Review

**When:** After NeuroSploit + Guardian attack chains + privesc/lateral movement.

### What Hermes Shows

```
Exploitation results:
  ✅ 10.0.2.5   UniFi Controller  EXPLOITED  (admin:unifi2020!)
       → SSID PSK extracted
       → 47 AP SSH keys recovered
       → Lateral: root on AP 10.0.2.12 via CVE-2024-1086

  ✅ 10.0.1.10  Exchange 2016     EXPLOITED  (ProxyShell)
       → SYSTEM shell obtained

  ✅ 10.0.1.50  MSSQL Server      EXPLOITED  (via SVC_SQL + xp_cmdshell)
       → Domain KRBTGT hash extracted via Mimikatz
       → DOMAIN DOMINANCE achieved

  ❌ 10.0.1.2   Domain Controller NOT EXPLOITED
       → NTLM relay captured, but SMB signing enforced — relay blocked

OPSEC: No IDS alerts detected. No accounts locked.
```

### What to Look For

- **Evidence quality** — screenshots, hashes, command output. Can you reproduce this?
- **Privilege level** — user? admin? SYSTEM? Domain Admin? Higher is better proof.
- **Lateral movement** — did exploitation chain to other hosts? This is good (shows blast radius) but means more hosts are now compromised.
- **Redaction needed?** — hashes, internal hostnames, PII in packet captures, actual passwords. Strip these before the report if the client doesn't want raw creds in a document.
- **OPSEC concerns** — did any IDS fire? Any accounts get locked? Mention these if the client's blue team was watching.

### When to RERUN

- "The DC wasn't exploitable — try a different relay target or Kerberoasting."
- "Retry the Exchange exploit with a different payload."
- "Run a full privesc check on the compromised Linux hosts."

### When to MODIFY SCOPE

- "Lateral movement found a new subnet (10.0.20.0/24). Add it to scope and return to Phase 1."

---

## Gate 4 — Report Review & Delivery

**When:** After report generation. Before client sees anything.

### What Hermes Shows

```
Reports generated:
  reports/portshim-report-20260701.docx  (42 pages, 67 findings)
  reports/portshim-brief-20260701.pptx   (12 slides)
  reports/checklist.xlsx                        (67 items, colour-coded)

Severity breakdown:
  Critical: 12  |  High: 34  |  Medium: 89  |  Low: 12

Key recommendations:
  1. Patch Exchange 2016 immediately (CVE-2021-34473)
  2. Segment UniFi management from corporate network
  3. Enforce LDAP signing + channel binding on all DCs
  4. Disable xp_cmdshell on MSSQL
```

### What to Check

- [ ] Reports exist and open correctly
- [ ] Severity ratings look right (a CVSS 9.8 shouldn't be "Medium")
- [ ] Findings are complete (evidence attached, remediation steps actionable)
- [ ] Redactions applied (no raw passwords, no internal hostnames if you stripped them)
- [ ] Executive brief makes sense without reading the technical report
- [ ] Checklist is usable (can a project manager actually track with it?)

### When to RERUN

- "Regenerate with the SSD template instead of default."
- "The executive brief needs better charts — regenerate with `--charts`."
- "Remove finding #34 — it's a false positive we confirmed at Gate 2."

---

## Gate 5 — Retest Sign-Off

**When:** After the client remediates and you re-scan.

### What Hermes Shows

```
Retest results (baseline vs retest):
  FIXED:        48 / 67  (71.6%)
  STILL OPEN:   12 / 67  (17.9%)
  NEW:           3
  REGRESSION:    2

STILL OPEN (high priority):
  CVE-2021-34473  Exchange 2016  —  patch not applied
  CVE-2021-26855  Exchange 2016  —  patch not applied

NEW findings:
  CVE-2024-xxxx  Newly discovered on web server (was not in baseline)
```

### What to Look For

- **Fix rate** — 70%+ is good. Below 50% means the client didn't take it seriously.
- **STILL OPEN Criticals** — these need immediate escalation.
- **REGRESSIONs** — something that was fixed is now broken again. This needs investigation.
- **NEW findings** — expected (new vulnerabilities are discovered constantly) but flag them.

### When to RERUN

- "The client says Exchange IS patched. Let me verify the version string manually."
- "Rescan just the STILL OPEN hosts to confirm."

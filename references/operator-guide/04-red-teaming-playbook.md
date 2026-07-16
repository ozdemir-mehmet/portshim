# Red Teaming Playbook

> A practical guide for conducting adversary-simulation engagements with PortShim.  
> Not a compliance checklist. Not a vulnerability scan. Think like an attacker.

---

## What This Is

The Operator's Quick Start tells you which commands to run.  
The Phase Decision Guide tells you what to decide at each gate.  
The Pre-Engagement Checklist tells you what to prepare.

This playbook tells you **how to think** during an engagement. It covers tactics, techniques, decision trees, and real-world attack patterns — mapped to PortShim's phases.

---

## Red Team vs Vulnerability Assessment

| | Vulnerability Assessment | Red Team Engagement |
|---|---|---|
| **Goal** | Find all vulnerabilities | Achieve specific objectives |
| **Approach** | Broad coverage | Targeted, chained attacks |
| **Output** | List of findings | Proof of impact |
| **Mindset** | "What's wrong?" | "How do I win?" |
| **Stealth** | Optional | Required |
| **Example objective** | "Find all CVEs" | "Access the PCI cardholder data environment" |

PortShim can do both. The stealth profiles and review gates let you switch between modes. This playbook assumes you're in **adversary-simulation mode** — objectives, stealth, and impact.

---

## Phase 0: Setting Objectives

Before you touch a keyboard, define what success looks like.

### Objective Types

| Type | Example | Validation |
|---|---|---|
| **Access** | Gain Domain Admin on corp.local | Golden Ticket generated, KRBTGT hash extracted |
| **Data** | Exfiltrate source code from git server | Tarball transferred to attacker-controlled host |
| **Persistence** | Maintain access for 7 days | C2 beacon checking in daily |
| **Lateral** | Move from guest Wi-Fi to internal file server | SMB share listing captured |
| **Impact** | Demonstrate ability to disrupt operations | Service account disabled, incident response triggered |

### Objective Stack (Pick 1-3)

Start with one primary objective. If you achieve it early, escalate to the next.

```
PRIMARY:   Access Domain Admin
SECONDARY: Exfiltrate HR database
BONUS:     Persist for 72 hours undetected
```

### Rules of Engagement

| Rule | Why |
|---|---|
| No denial of service unless authorised | You're testing security, not breaking production |
| No password changes | You're not the admin — don't lock people out |
| Stop on detection signal | If the blue team spots you, debrief — don't evade |
| Capture evidence at every step | Screenshots, hashes, command output, timestamps |

---

## Phase 1: Reconnaissance — Think Like an Attacker

An attacker doesn't care about every host. They care about the hosts that help them achieve their objective.

### Target Prioritisation

When `device-classifier.py` returns 847 hosts, don't scan all of them. Ask:

1. **Which hosts help me achieve my objective?**
   - Domain Admin objective → Domain Controllers, any host with admin sessions
   - Data exfiltration objective → File servers, database servers, backup servers
   - Lateral movement objective → Jump hosts, management interfaces, Wi-Fi controllers

2. **Which hosts are easy to compromise?**
   - IoT devices (cameras, NVRs, building management)
   - Default credentials (printers, network gear, appliances)
   - Unpatched edge services (VPN, Exchange, web apps)
   - Wireless (if PSK is weak or WPA2-Enterprise has misconfigurations)

3. **Which hosts have privileged context?**
   - Management workstations (IT admin desktops)
   - Build servers (CI/CD with deployment credentials)
   - Monitoring systems (SNMP with read/write community strings)
   - Backup infrastructure (access to everything)

### The Pivot Chain Mentality

Don't think "I need to own the Domain Controller." Think:

> "I need a foothold → I need credentials → I need a context with access to the DC."

```
Foothold (IoT device) → Credential harvesting (ARP spoofing) → 
Service account → MSSQL with xp_cmdshell → SYSTEM → 
Token theft (mimikatz) → Domain Admin
```

Every host is a stepping stone, not an endpoint.

### Stealth in Reconnaissance

| Profile | Risk of Detection | Information Gained | When to Use |
|---|---|---|---|
| Silent Entry | Minimal | Limited but enough to find footholds | IDS present, objective requires stealth |
| Surgical | Low | Good coverage of high-value targets | Default — start here |
| Full Assault | High | Complete | Only if speed matters more than stealth |

**Rule of thumb:** Start Surgical. If you find a high-confidence path to your objective, switch to Silent Entry for exploitation. If time is critical and detection doesn't matter, go Full Assault.

---

## Phase 2: Vulnerability Analysis — Find the Weakest Link

An attacker doesn't need every vulnerability. They need one that chains to their objective.

### The CVSS Trap

CVSS scores measure severity, not exploitability-for-your-objective. A CVSS 9.8 on an internet-facing service is gold. A CVSS 9.8 on an internal-only development server is useful only if you can reach it.

**Ask at Gate 2:**

- Can I reach this host? (Network path exists?)
- Does this CVE have a public exploit? (PoC available?)
- If I exploit this, what does it give me? (User access? Admin? Code execution?)
- Does this help my objective? (Or is it a distraction?)

### Finding Prioritisation Matrix

| | High Value (helps objective) | Low Value |
|---|---|---|
| **Easy Exploit** | 🔴 **EXPLOIT FIRST** | ⚠️ Opportunistic |
| **Hard Exploit** | 🟡 Plan for later | ❌ Skip |

### Common Attack Chains

#### Chain 1: Network Appliance to Domain
```
UniFi Controller (default creds) → SSH keys for APs → 
Packet capture from AP → Cleartext LDAP → Domain credentials
```

#### Chain 2: Web App to Cloud
```
Web app (SQLi) → Database → Stored cloud API keys → 
AWS metadata service → IAM role → S3 bucket → Customer data
```

#### Chain 3: Phishing to Persistence
```
Phishing email → User workstation → Cached credentials → 
Lateral to file server → Scheduled task for persistence → 
C2 beacon
```

#### Chain 4: Wi-Fi to Internal Network
```
WPA2-PSK cracked → Join corporate network → 
LLMNR poisoning → NTLMv2 hash → Crack offline → 
Service account → Domain join rights → New domain computer
```

### When to Skip a Finding

Skip a finding at Gate 2 when:
- It's out of scope
- It requires an exploit that would be destructive (DoS, data corruption)
- It's on a host you can't reach from your current position
- The CVE has no known public exploit and developing one exceeds engagement timeline
- Exploiting it would alert the blue team before you've achieved your objective

---

## Phase 3: Exploitation — Execute the Chain

### Before You Exploit

At Gate 2, you selected targets. Before running exploits, ask:

1. **OPSEC:** Will this trigger alerts? If using Silent Entry, test on a low-risk target first.
2. **Order:** Exploit the easiest target that gives the most access first. Build momentum.
3. **Fallback:** If the exploit fails, what's plan B? Have alternatives ready.

### Exploitation Order (Default Priority)

```
1. Default credentials (fastest, least risky)
2. Unauthenticated RCE (no creds needed)
3. Authenticated RCE (needs creds you already have)
4. Privilege escalation (from user to admin/SYSTEM)
5. Credential harvesting (from memory, LSASS, SAM)
6. Lateral movement (to next host in chain)
7. Persistence (scheduled task, service, WMI subscription)
```

### Evidence Capture

Every successful exploitation step must produce:

| Evidence Type | Example | Tool |
|---|---|---|
| **Access proof** | Screenshot of shell with `whoami` output | Terminal capture |
| **Credential proof** | Hash of extracted password | `hashcat --show` output |
| **Lateral proof** | Directory listing on target host | `dir \\target\c$` |
| **Persistence proof** | Scheduled task creation confirmed | `schtasks /query` |
| **Timestamp** | `date /t && time /t` at each step | Built-in commands |

**Never** include raw password hashes or PII in the report unless the client explicitly requests it. Redact at Gate 3.

### When Exploitation Fails

| Failure | Response |
|---|---|
| Exploit doesn't work | Try alternative CVE, different payload, different timing |
| Target is patched | Move to next target — document as "patched, not exploitable" |
| AV/EDR blocks payload | Try different technique (PowerShell → WMI → scheduled task) |
| Account gets locked | **Stop immediately.** Notify the point of contact. Switch to passive recon. |
| IDS alert fires | Assess: was it a false positive? If real, debrief with blue team. |

### Privilege Escalation Checklist

On a compromised Linux host:
```
1. sudo -l (what can you run as root?)
2. find / -perm -4000 -type f 2>/dev/null (SUID binaries)
3. crontab -l (scheduled tasks running as root?)
4. env (any sensitive environment variables?)
5. uname -a (kernel version — any known exploits?)
```

On a compromised Windows host:
```
1. whoami /priv (which privileges are enabled?)
2. net localgroup Administrators (who's admin?)
3. schtasks /query /fo LIST /v (scheduled tasks)
4. wmic service get name,pathname,startname (services running as SYSTEM?)
5. reg query HKLM\SYSTEM\CurrentControlSet\Services (unquoted service paths)
```

---

## Phase 4: Reporting — Tell the Story

A red team report is not a list of findings. It's a narrative.

### The Narrative Arc

```
1. Here's what an attacker would do
2. Here's how they'd do it (your attack chain)
3. Here's what they'd get (your objective)
4. Here's the impact
5. Here's how to stop them
```

### Example Narrative (Bad vs Good)

**Bad:** "CVE-2021-34473 was found on Exchange server 10.0.1.10. CVSS 9.8. Patch immediately."

**Good:** "An attacker with network access could exploit an unpatched Exchange server (10.0.1.10) to gain SYSTEM-level access without credentials. From there, they could extract the domain KRBTGT hash from memory, forge Golden Tickets, and access every domain-joined system — including the PCI cardholder data environment on the Hyper-V cluster. This entire chain took 27 minutes. The root cause is a missing security patch from 2021."

### Impact Statements

| Finding | Don't Say | Say |
|---|---|---|
| Weak AD config | "LDAP signing is off" | "An attacker on the network can impersonate any domain user, including Domain Admins, by relaying NTLM authentication" |
| Unpatched server | "Exchange is missing patches" | "An attacker can gain SYSTEM access to the email server, read all executive email, and pivot to the domain controller" |
| Default credentials | "UniFi has default admin password" | "An attacker can access the wireless controller, extract SSH keys for every access point on campus, and capture cleartext domain credentials from network traffic" |

### The Executive Brief

The CISO doesn't care about CVSS vectors. They care about:

1. **What's the worst that can happen?** (One sentence)
2. **How did you prove it?** (The attack chain, high level)
3. **What do we fix first?** (Top 3 actions, prioritised)
4. **How long would a real attack take?** (Time from foothold to objective)

---

## Phase 5: Retest — Verify the Fix

### What to Retest

Not every finding. Focus on:

1. **Critical and High severity** — if these aren't fixed, the engagement was pointless
2. **Findings that enabled your attack chain** — if the pivot point is still open, everything downstream is still vulnerable
3. **New systems** — if the client deployed new infrastructure during remediation

### Red Team Retest Mindset

A vulnerability scan retest checks if patches were applied.  
A red team retest checks if the **attack chain still works**.

If the client patched Exchange but didn't fix LDAP signing, they closed the front door but left the window open. Your retest should attempt the full chain with the remaining open vectors.

### When Findings Aren't Fixed

| Reason | Response |
|---|---|
| "We accepted the risk" | Document, close finding as ACCEPTED RISK |
| "We can't patch it" | Recommend compensating controls (network segmentation, MFA, monitoring) |
| "It's a false positive" | Re-verify, provide evidence it's real |
| "We forgot" | Escalate — this is a process failure |

---

## Common Attack Patterns (Reference)

### Pattern 1: The Flat Network

**Scenario:** No VLAN segmentation. Every host can reach every other host.  
**Strategy:** Compromise the weakest host (IoT, printer, default creds). From there, ARP spoof, LLMNR poison, or SMB relay to harvest credentials. Escalate to Domain Admin.  
**Impact:** Full domain compromise from a single entry point.  
**Remediation:** Network segmentation, NAC, disable LLMNR/NetBIOS, enforce SMB signing.

### Pattern 2: The Cloud Bridge

**Scenario:** On-premises network with cloud connectivity (AWS Direct Connect, Azure ExpressRoute).  
**Strategy:** Compromise an on-prem host. Discover cloud credentials in config files, environment variables, or credential stores. Use cloud access to reach cloud resources (S3 buckets, Azure VMs, IAM roles).  
**Impact:** On-prem compromise leads to cloud data exfiltration.  
**Remediation:** Separate cloud credentials from on-prem systems, use IAM roles instead of long-lived keys, monitor cross-premises access patterns.

### Pattern 3: The Wireless Weakness

**Scenario:** Corporate Wi-Fi with WPA2-PSK and a weak passphrase.  
**Strategy:** Capture WPA handshake (deauth attack). Crack offline (dictionary, hashcat). Join corporate network. From internal access, enumerate and attack domain resources.  
**Impact:** Wireless PSK crack leads to full internal network access.  
**Remediation:** WPA2-Enterprise with 802.1X, certificate-based authentication, network access control.

### Pattern 4: The Supply Chain

**Scenario:** Third-party vendor has VPN access for support.  
**Strategy:** Identify vendor access patterns. Target the vendor's VPN concentrator or jump host. If the vendor's network is weaker, compromise the vendor first, then pivot through the VPN.  
**Impact:** Trusted third-party access becomes attacker access.  
**Remediation:** Vendor access segmentation, just-in-time access, session monitoring and recording.

---

## Stealth Profile Decision Tree

```
Is there an active IDS/IPS? ──Yes──→ SILENT ENTRY
    │
    No
    │
    ▼
Is the engagement time-critical? ──Yes──→ FULL ASSAULT
    │
    No
    │
    ▼
SURGICAL (default)
```

**You can change profiles between phases:**
- Recon: Surgical (find everything)
- Exploitation: Silent Entry (don't get caught during the critical phase)
- Reporting: N/A

---

## Objective-Based Execution Checklist

Before starting each phase, answer:

**Phase 1 (Recon):**  
- [ ] What's my primary objective?  
- [ ] Which hosts are most likely to help me achieve it?  
- [ ] Am I starting Surgical and switching to Silent Entry for exploitation?

**Phase 2 (Analysis):**  
- [ ] Which findings chain together toward my objective?  
- [ ] Which findings are distractions I should skip?  
- [ ] Do I have at least two attack paths? (If path A fails, path B must exist)

**Phase 3 (Exploitation):**  
- [ ] Am I exploiting in priority order (easy→hard, foothold→objective)?  
- [ ] Is evidence being captured at every step?  
- [ ] Do I have a fallback for each target?

**Phase 4 (Reporting):**  
- [ ] Does the report tell a story, not just list findings?  
- [ ] Are impact statements clear for non-technical readers?  
- [ ] Are remediation steps actionable (specific patch, specific config change)?

**Phase 5 (Retest):**  
- [ ] Did the client fix the findings that enabled my attack chain?  
- [ ] Can I still achieve the original objective?  
- [ ] Are there new attack paths from new infrastructure?

---

## Quick Reference Card

| Situation | Action |
|---|---|
| Found default credentials | Test immediately — fastest path to foothold |
| Found unpatched Exchange | High priority — often leads to SYSTEM/Domain Admin |
| Service account with local admin | Extract tokens, check where the account has access |
| LDAP signing disabled | Set up NTLM relay — this is your lateral movement highway |
| No east-west filtering | Compromise any host, pivot from there — network is your oyster |
| WPA2-PSK, weak password | Capture handshake, crack offline — instant internal access |
| SMB signing disabled | Relay attack — no credentials needed |
| xp_cmdshell enabled on MSSQL | SYSTEM access on the database server — extract everything |
| Backup server found | Contains copies of everything — treat as high-value target |
| Blue team detects you | Stop. Debrief. This is a training opportunity, not a failure. |

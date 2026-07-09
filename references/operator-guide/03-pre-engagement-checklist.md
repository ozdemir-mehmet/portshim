# Pre-Engagement Checklist

> Complete this before every engagement. Check off each item.

---

## Authorisation

- [ ] **Signed authorisation letter** from the network owner or authorised representative
- [ ] Letter specifies:
  - [ ] Target IP ranges / CIDR blocks
  - [ ] Wireless SSIDs in scope (if applicable)
  - [ ] Testing window (start and end date/time)
  - [ ] Physical testing location(s)
  - [ ] Point of contact (name, phone, email)
- [ ] **Out-of-scope systems documented** (printers? VoIP? OT/ICS? medical devices?)
- [ ] **Emergency stop procedure** — who to call if something breaks, how to halt testing

> ⚠️ **Never begin without the signed letter.** No authorisation = no testing.

---

## Hardware

- [ ] **Laptop** — Linux (Ubuntu 22.04+, Fedora 38+, Debian 12+, or similar)
- [ ] **Power adapter** — you may be in a server room or meeting room without easy outlets
- [ ] **Ethernet cable** — for wired network connection (Cat5e or better, at least 3 meters)
- [ ] **USB-to-Ethernet adapter** — if your laptop lacks a native RJ45 port

### Wireless Testing (only if wireless is in scope)

- [ ] **External Wi-Fi adapter** — Alfa AWUS036ACH (recommended) or equivalent with monitor mode + packet injection
- [ ] **Adapter tested** before arriving on-site:
  ```bash
  lsusb | grep -i alfa          # Is it detected?
  airmon-ng start wlan0          # Monitor mode works?
  aireplay-ng --test wlan0mon    # Injection works?
  ```
- [ ] **Spare adapter** — if budget allows. A single $35 Alfa card is your entire wireless capability.

> The Phase 1.3 pre-flight check will catch a missing adapter and document the limitation. But the report will say "Wireless Assessment Partial." Bring the card.

---

## Software

- [ ] **PortShim updated** — `git pull` in the project directory
- [ ] **Knowledge synced** — `python scripts/sync_knowledge.py --all`
- [ ] **Freshness checked** — `python scripts/check-skill-freshness.py` (no >30 day stale repos)
- [ ] **Nuclei templates updated** — `nuclei -update-templates`
- [ ] **Hermes installed and authenticated** — `hermes doctor` shows all green
- [ ] **Stealth profile selected** — `python skills/site-assessment-pipeline/scripts/stealth-profiles.py <profile>`
- [ ] **LLM mode configured** — `python skills/site-assessment-pipeline/scripts/llm-config.py <mode>`

---

## Target Information

Gather as much as you can before arriving. Fill this out:

```
Target IP range(s):   _________________________________
Wireless SSIDs:       _________________________________
Known exclusions:     _________________________________
Network type:         ☐ Flat (single subnet)  ☐ Segmented (VLANs)  ☐ Unknown
Wireless in scope?    ☐ Yes  ☐ No
Known technologies:   ☐ Windows AD  ☐ Exchange  ☐ MSSQL  ☐ Linux  ☐ Cloud (AWS/Azure/GCP)
IDS/IPS present?      ☐ Yes  ☐ No  ☐ Unknown
NAC (802.1X)?         ☐ Yes  ☐ No  ☐ Unknown
Expected host count:  _________________________________
Physical location:    ☐ Meeting room  ☐ Server room  ☐ IDF closet  ☐ Multiple locations
```

---

## Stealth Profile Decision

| If... | Use |
|---|---|
| IDS/IPS is present and active | **Silent Entry** — slow, quiet, single-threaded |
| Standard assessment, no known monitoring | **Surgical** — balanced, rate-limited, default |
| Time-critical, full coverage required | **Full Assault** — fast, multi-threaded, everything |

> You can change the profile between phases (e.g., Surgical for recon, Silent Entry for exploitation).

---

## LLM Mode Decision

| If... | Use |
|---|---|
| Air-gapped site, no internet | **Local** — everything on laptop GPU |
| Field laptop with decent GPU | **Hybrid** — exploits local, reports via cloud |
| Thin client, no GPU | **Cloud** — everything via DeepSeek API |

> Cloud mode needs an internet connection. Local mode needs a GPU. Hybrid is usually right.

---

## Post-Engagement

- [ ] **Report delivery method** determined (encrypted email? USB? secure portal?)
- [ ] **Data retention policy** understood — how long do you keep scan data and findings?
- [ ] **Retest window** scheduled — when will the client have fixes ready for Phase 5?
- [ ] **Debrief meeting** scheduled with client stakeholders

---

## Quick Pre-Flight (Run These On-Site)

Before telling Hermes to start:

```bash
# 1. Am I on the target network?
ping <target gateway>

# 2. Do I have internet? (skip for air-gapped / local mode)
curl -s https://api.github.com | head -1

# 3. Is Hermes working?
hermes doctor

# 4. Wireless pre-flight (if wireless in scope):
lsusb | grep -iE 'alfa|realtek|atheros'
airmon-ng start wlan0
aireplay-ng --test wlan0mon
```

All green? Load the skill and start:

```
/skill site-assessment-pipeline
```

---

## Emergency Contacts

| Role | Name | Phone | Notes |
|---|---|---|---|
| Site contact | | | |
| Escalation (if something breaks) | | | |
| Your team lead | | | |

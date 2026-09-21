# Video Script: Operator's Quick Start
# Source: references/operator-guide/01-quick-start.md
# Duration target: ~8 minutes
# Narrator: Professional, calm, instructive

---

## SCENE 1 — INTRO (0:10)
**Visual:** PortShim title card fading in on dark background. "On-Site Security Assessment Pipeline" subtitle appears below. Red accent bar animates across the bottom.
**Audio:** (Brief musical sting — 2 seconds — then fade to narration)

PortShim. On-site security assessment — automated, operator-controlled, and ready to deploy.

This is the Operator's Quick Start.

---

## SCENE 2 — INTRODUCTION (0:30)

You've got a target. You've got authorisation. Now you need to know how to actually run the assessment. That's what this guide is for.

PortShim is an on-site security assessment pipeline. It maps your target network, finds vulnerabilities, verifies which ones are actually exploitable, and produces professional reports — all with you making the decisions at review gates between each phase.

This video walks you through it, step by step. No theory, just commands.

---

## SCENE 3 — WHAT YOU NEED (0:40)

**Visual:** Checklist items appearing one by one

Before you start, here's what you'll need.

First, a Linux laptop. Ubuntu 22.04 or later, Fedora 38 or later, Debian 12 — any modern distro works.

Second, a signed authorisation letter. This must specify your target IP range, any wireless SSIDs if wireless testing is in scope, and your testing window. Do not begin without this.

Third, your target information — at minimum the IP range. Something like ten dot zero dot zero dot zero slash twenty-two.

Fourth, internet access. You'll need it for the initial deployment and to sync the latest vulnerability data. After that, if you're running in local mode, you can go fully air-gapped.

And finally, if wireless testing is in scope — an external Wi-Fi adapter that supports monitor mode and packet injection. The Alfa AWUS036ACH is the standard. It's about thirty-five dollars. The pre-flight check in Phase 1 will tell you if you're missing it.

---

## SCENE 4 — STEP 1: DEPLOY (0:25)

**Visual:** Terminal window showing git clone and deploy.py output

Step one. Clone the repository and run the deploy script.

```bash
git clone https://github.com/ozdemir-mehmet/portshim.git
cd portshim
python deploy.py
```

That's it. One command. Deploy detects your Linux distribution and installs everything — nmap, nuclei, httpx, subfinder, all Python dependencies, and twenty-five cybersecurity skills from Anthropic. It takes about two minutes.

---

## SCENE 5 — STEP 2: SYNC KNOWLEDGE (0:20)

**Visual:** Terminal showing sync command and progress

Step two. Before every engagement, sync the latest data.

```bash
python scripts/sync_knowledge.py --all
python scripts/check-skill-freshness.py
```

This pulls the latest CVE database, exploit signatures, and skill updates from seven tracked GitHub repositories. It also checks whether any source is more than thirty days stale. Thirty seconds, and you're current.

---

## SCENE 6 — STEP 3: CONFIGURE (0:35)

**Visual:** Decision table for stealth profiles and LLM modes

Step three. Pick your stealth profile and your LLM mode.

The stealth profile controls how aggressive your scanning is. Silent Entry is for networks with intrusion detection — single-threaded, thirty-second delays, no brute force. Surgical is the default — rate-limited, balanced, good for most assessments. Full Assault is for when time is critical — multi-threaded, everything turned on.

```bash
python skills/site-assessment-pipeline/scripts/stealth-profiles.py surgical
```

The LLM mode controls where the AI processing happens. Local mode runs everything on your laptop's GPU — this is for air-gapped sites. Hybrid mode keeps tactical scanning and exploitation local but uses cloud APIs for report generation. Cloud mode runs everything through the API — good for thin clients with no GPU.

```bash
python skills/site-assessment-pipeline/scripts/llm-config.py hybrid
```

For most engagements, Surgical plus Hybrid is the right call.

---

## SCENE 7 — STEP 4: LOAD THE PIPELINE (0:15)

**Visual:** Hermes terminal showing /skill command

Step four. Load the orchestrator into Hermes.

Type forward slash skill, space, site dash assessment dash pipeline.

From this point, Hermes is your operator. It will walk you through every phase and stop at every gate for your approval.

---

## SCENE 8 — STEP 5: START THE ENGAGEMENT (0:50)

**Visual:** Animated phase diagram showing the pipeline flow

Step five. Tell Hermes your target. Something like:

"Start Phase 0. Target is ten dot zero dot zero dot zero slash twenty-two. Wireless not in scope. Use the current config."

Here's what happens next.

First, Phase 0 confirms your scope at Gate 0. You verify the IP range is correct, the stealth profile makes sense, and wireless is correctly toggled on or off.

Then Phase 1 runs — reconnaissance. Nmap discovers every live host on the network. The device classifier identifies what each host actually is — domain controllers, IoT devices, NVRs, hypervisors, everything. At Gate 1, you review the network map. Too many unknowns? Rerun with deeper scanning. Missed a subnet? Modify the scope.

Phase 2 cross-references every discovered service against the CVE database. You get a prioritised list of vulnerabilities with CVSS scores. At Gate 2 — and this is the most important gate — you select exactly which targets to exploit. Hermes will only touch hosts you explicitly approve.

Phase 3 verifies those exploits. It attempts privilege escalation, lateral movement, and captures evidence. At Gate 3, you review the exploitation evidence. You can redact sensitive information — hashes, internal hostnames — before anything goes into the report.

Phase 4 generates the deliverables — a technical Word document, an executive PowerPoint brief, and an Excel remediation checklist with colour-coded severity ratings and tick columns.

At Gate 4, you review the reports. Only when you approve do they go to the client.

---

## SCENE 9 — WHAT YOU DO AT EACH GATE (0:30)

**Visual:** Decision matrix: APPROVE / RERUN / MODIFY SCOPE / ABORT

At every gate, Hermes presents a summary and waits. You have four options.

APPROVE means the output looks correct — proceed to the next phase.

RERUN means something's off — repeat the phase with different parameters. Maybe a wider subnet scan. Maybe all ports instead of the default set. Maybe a different stealth profile.

MODIFY SCOPE means the target range itself needs changing. Add wireless. Remove a subnet. Expand the CIDR.

And ABORT stops everything immediately. All outputs are saved.

You cannot auto-advance. Hermes will always wait for you.

---

## SCENE 10 — WHAT YOU GET (0:25)

**Visual:** File icons appearing with descriptions

After Phase 4, in your reports directory, you'll find three files.

The technical report — a Word document with every finding, CVSS scores, reproduction steps, and prioritised remediation. This is for engineers and the security team.

The executive brief — a PowerPoint deck with risk summaries, top findings, and recommended actions. This is for the CISO and management.

And the remediation checklist — an Excel spreadsheet, colour-coded by severity, with tick columns for tracking fixes. This is for the project manager or the remediation owner.

---

## SCENE 11 — RETESTING (0:25)

**Visual:** Before/after comparison showing FIXED / STILL OPEN / NEW / REGRESSION

After the client remediates, Phase 5 handles retesting.

Reload the skill and select Phase 5. Hermes rescans the network, compares against the baseline, and classifies every finding.

FIXED means the vulnerability was successfully remediated. STILL OPEN means it was not fixed. NEW means something was discovered that wasn't in the baseline scan. And REGRESSION means something that was previously fixed is now broken again.

The checklist updates automatically — ticks for resolved items, retest dates, and highlighted new findings.

---

## SCENE 12 — WIRELESS TESTING (0:25)

**Visual:** Alfa card connecting to laptop, pre-flight check terminal output

If wireless is in scope, Phase 1.3 runs a hardware pre-flight check.

It tests for an external adapter, verifies monitor mode, and checks packet injection capability. If the Alfa card is connected and injection works, you get a full wireless penetration test — evil twin attacks, WPA handshake capture, WPA3 downgrade testing.

If only the internal laptop Wi-Fi is available, the pipeline runs Kismet passive monitoring — it can still detect rogue access points, hidden SSIDs, and weak encryption — but active attacks are skipped. The limitation is documented in the report with a clear recommendation to retest with proper hardware.

---

## SCENE 13 — TROUBLESHOOTING (0:20)

**Visual:** Common problems and fixes on screen

Three common problems, and what to do.

No hosts found? Check your IP range — try pinging the gateway first.

Nmap complains about root permissions? Deploy handles this automatically, but if you're running manually, use dash s T for TCP connect scans instead of SYN.

Report won't generate? You're probably missing the Python dependencies. Run pip install openpyxl python-docx python-pptx.

---

## SCENE 14 — OUTRO (0:15)

**Visual:** PortShim title, GitHub URL

That's the operator's quick start. Clone the repo, run deploy, sync knowledge, pick your profile, load the skill, and tell Hermes your target. The pipeline handles the rest — with you in control at every gate.

Full documentation at the GitHub repository. Link in the description.

---

---

## SCENE OUTRO — END CARD (0:15)
**Visual:** PortShim title fades back in. GitHub URL centred below: github.com/ozdemir-mehmet/portshim. Red accent bar fades in at top.
**Audio:** (Narration over gentle background music)

That concludes Operator's Quick Start. Full documentation, printable checklists, and all source code are available at the GitHub repository linked below.

PortShim is open source under the MIT licence. Contributions and feedback are welcome.

(Brief musical fade-out)

---


## PRODUCTION NOTES

- Total estimated duration: ~7 minutes
- Slide count target: 14 scenes
- Voice: Calm, professional, Australian accent preferred
- Code blocks: Show as terminal-style overlays, not read character-by-character
- Gate decision matrix: Animate as a flow chart

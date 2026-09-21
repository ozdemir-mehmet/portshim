# Video Script: Phase-by-Phase Decision Guide
# Source: references/operator-guide/02-phase-decision-guide.md
# Duration target: ~14 minutes
# Narrator: Professional, calm, instructive

---

## SCENE 1 — INTRO (0:10)
**Visual:** PortShim title card fading in on dark background. "On-Site Security Assessment Pipeline" subtitle appears below. Red accent bar animates across the bottom.
**Audio:** (Brief musical sting — 2 seconds — then fade to narration)

PortShim. On-site security assessment — automated, operator-controlled, and ready to deploy.

This is the Phase-by-Phase Decision Guide.

---

## SCENE 2 — INTRODUCTION (0:30)

PortShim has six phases, and between every phase, there's a review gate. At each gate, you — the operator — decide whether to approve and proceed, rerun with changes, modify the scope, or abort.

This video walks through exactly what you'll see at each gate, what to look for, and when to make each decision. If you've watched the Quick Start, this is the deep dive on the decision points.

---

## SCENE 3 — GATE 0: ENGAGEMENT CONFIRMATION (1:00)

**Visual:** Gate 0 summary screen mockup

Gate 0 happens after setup, before any scanning begins. Hermes shows you the configuration it's about to use.

You'll see the target IP range — something like ten dot zero dot zero dot zero slash twenty-two. You'll see the stealth profile — Surgical, Silent Entry, or Full Assault. The LLM mode — Local, Hybrid, or Cloud. Whether wireless testing is in scope. And any exclusions you've provided.

Your job here is simple but critical. Before you approve, verify three things.

First — is the IP range correct? A wrong subnet means you scan the wrong network. If the engagement scope says slash twenty-four and you typed slash twenty-two, fix it now.

Second — does the stealth profile match the environment? If the client mentioned they have intrusion detection, switch to Silent Entry. Surgical is right for most assessments, but if you need to be quiet, say so.

Third — is wireless correctly toggled? It defaults to off. If there's a corporate Wi-Fi network in scope, turn it on now.

This is a config check, not a scan. Just adjust any values that are wrong and approve.

---

## SCENE 4 — GATE 1: RECONNAISSANCE REVIEW (1:30)

**Visual:** Sample Gate 1 output — host count, device breakdown, high-risk flags

Gate 1 comes after nmap has scanned the network and the device classifier has identified what everything is. Hermes shows you the live host count, a breakdown by device type, a list of high-risk flagged hosts, and a topology summary.

Here's what to check.

First — does the host count make sense? Eight hundred and forty-seven hosts on a slash twenty-two is plausible. Three hosts on a corporate slash sixteen probably means something is wrong — VLAN isolation, a firewall blocking probes, or the wrong subnet.

Second — are the device roles sane? If every host is showing as Unknown, your fingerprinting is too passive. Switch to Surgical or Full Assault for deeper probing. You should see domain controllers, servers, workstations, IoT devices, network infrastructure — real categories.

Third — do the high-risk flags pass the sniff test? A domain controller flagged for LDAP signing enforcement is normal and expected. A printer flagged as Critical is probably a false positive. Phase 2 will sort these out.

The wireless pre-flight result is also shown here — FULL means ready to go, PASSIVE ONLY means monitor mode works but injection doesn't, ATTEMPTED means nothing worked, NONE means no adapter was found.

When do you rerun? If too many devices are Unknown, rescan with deeper settings. If the host count is too low, check if the subnet is larger than you thought or if a firewall is blocking. And if wireless pre-flight failed, connect the Alfa card and re-run.

When do you modify scope? If you missed a subnet, add it. If wireless needs to be added, enable it. If the scan is too noisy, switch to Silent Entry.

---

## SCENE 5 — GATE 2: FINDINGS REVIEW AND TARGET SELECTION (2:30)

**Visual:** Gate 2 — severity counts, top 10 findings table, target selection prompt

Gate 2 is the most important gate in the entire pipeline. This is where you decide what gets exploited.

After Phase 2 completes, Hermes shows you the findings broken down by severity — Critical at CVSS nine point zero and above, High at seven point zero to eight point nine, Medium at four point zero to six point nine. You'll see the top findings ranked, each with the host, the CVE ID, the CVSS score, and a brief description.

Your job at this gate has three parts.

**Part one — spot false positives.** A Critical CVE on a printer usually means the version string matched but the vulnerability doesn't actually apply. If a finding says "exploit available" or "public proof of concept," it's high confidence. If it's a version match with no known exploit, it's lower priority.

**Part two — consider context.** A CVSS nine point eight on an internet-facing Exchange server is emergency-level. The same CVE on an internal-only development server is still bad but less urgent. The score is a starting point, not the whole story.

**Part three — exclude out-of-scope systems.** If a finding is on a host not covered by your authorisation letter, exclude it. No exceptions.

And then the critical decision: you must provide an explicit target list. Hermes will only exploit hosts you name. For example — "Exploit ten dot zero dot two dot five, ten dot zero dot one dot ten, ten dot zero dot one dot two, and ten dot zero dot one dot fifty. Skip ten dot zero dot five dot one hundred — it's out of scope."

When do you rerun? If nuclei missed something — run it with more templates on specific subnets. If you need more detail before deciding — rescan with all ports on the high-value targets. If a service version string looks suspicious — verify it manually.

When do you modify scope? If the findings reveal that a neighbouring subnet is relevant — add it. If you need a different stealth profile for deeper investigation — switch to Surgical or Full Assault.

---

## SCENE 6 — GATE 3: EXPLOITATION EVIDENCE REVIEW (2:00)

**Visual:** Exploitation results — exploited hosts with checkmarks, evidence paths, OPSEC summary

Gate 3 follows Phase 3 — exploitation. Hermes shows you which targets were successfully exploited, which were not, what privileges were obtained, any lateral movement chains that were established, and any operational security concerns.

For each exploited target, you'll see the evidence — the CVE that was used, the access level achieved, any credentials extracted, and any lateral movement paths.

Here's what to inspect.

Evidence quality — are there screenshots? Command output? Can you reproduce what the tool claims happened? If the evidence is thin, consider rerunning.

Privilege level — did you get user access, administrator, SYSTEM, or Domain Admin? Higher is better proof of impact, but document the actual level achieved.

Lateral movement — did exploitation chain from one host to another? This demonstrates blast radius, which is valuable for the report. But it also means more hosts are compromised — make sure those were in scope.

The redaction question — do you want raw password hashes in the client report? Internal hostnames? Personally identifiable information from packet captures? Gate 3 is your chance to strip these before Phase 4 generates the deliverables.

OPSEC concerns — did any intrusion detection system fire? Any accounts get locked? The client's blue team may be watching. Mention these if relevant.

When do you rerun? If a high-priority target wasn't exploitable — try a different approach. Different exploit. Different payload. Different timing. If privesc failed on a compromised host — try a more thorough check.

When do you modify scope? If lateral movement revealed a new subnet that wasn't in the original scope — you can add it and return to Phase 1. This is the only gate where scope expansion is driven by findings.

---

## SCENE 7 — GATE 4: REPORT REVIEW AND DELIVERY (1:30)

**Visual:** Three report files appearing, severity breakdown chart

Gate 4 comes after Phase 4 has generated all three deliverables — the technical Word document, the executive PowerPoint brief, and the Excel remediation checklist.

Hermes shows you the file paths, a severity breakdown, and the key recommendations.

Before you approve for client delivery, open each file and check these things.

The reports exist and open correctly — sounds obvious, but verify.

Severity ratings are consistent — a CVSS nine point eight should never appear as Medium. If something looks misclassified, regenerate.

Findings are complete — each one has evidence attached and actionable remediation steps. A finding that says "patch the server" without specifying which patch is incomplete.

Redactions are applied — if you stripped hashes or internal hostnames at Gate 3, confirm they're not in the report.

The executive brief stands alone — a CISO should understand the risk picture without reading the forty-page technical report.

The checklist is usable — can a project manager actually track remediation with it? Are the severity colours clear? Are there tick columns and date fields?

When do you rerun? If the formatting is wrong — regenerate with different templates. If the executive brief needs better charts — regenerate with chart options. If a specific finding needs to be removed — it was a confirmed false positive at Gate 2 — remove it and regenerate.

---

## SCENE 8 — GATE 5: RETEST SIGN-OFF (1:30)

**Visual:** Before/after comparison, fix rate percentage, classification table

Gate 5 is the final gate. It comes after Phase 5 — the retest. The client has implemented fixes, and you've rescanned to verify them.

Hermes presents the retest results — the fix rate as a percentage, how many findings are STILL OPEN, any NEW findings discovered since the baseline, and any REGRESSIONs where something that was fixed is now broken again.

Here's how to read the numbers.

A fix rate above seventy per cent is good. Below fifty per cent means the client didn't take the assessment seriously — this needs escalation.

STILL OPEN Criticals are the priority. If Exchange is still unpatched after the retest window, that's an urgent finding that needs immediate attention.

REGRESSIONs need investigation. Something was fixed, but it's broken again. That could mean the fix was incomplete, or a configuration change undid it, or the initial fix assessment was wrong.

NEW findings are expected — new vulnerabilities are discovered constantly. Flag them, score them, add them to the checklist.

When do you rerun? If the client claims something is fixed but the scan says otherwise — verify manually. Rescan just the STILL OPEN hosts to confirm.

When do you sign off? When the fix rate is acceptable, the STILL OPEN items are documented with clear remediation steps, and any REGRESSIONs have been investigated. Then approve. The engagement is complete.

---

## SCENE 9 — DECISION SUMMARY (1:00)

**Visual:** Full pipeline flow with all gates annotated

Let's recap every gate and its primary question.

Gate 0 — is my scope correct? Config check, quick approval.

Gate 1 — did we find everything on the network? Review the map, adjust if needed.

Gate 2 — which vulnerabilities do we exploit? The hard gate. You name the targets.

Gate 3 — is the evidence solid and clean? Review, redact, approve for reporting.

Gate 4 — are the reports client-ready? Open them, check them, then deliver.

Gate 5 — did the client actually fix things? Verify, classify, sign off.

At every gate, you have four options — APPROVE, RERUN, MODIFY SCOPE, or ABORT. Hermes will never proceed without you. The pipeline is powerful, but the operator is in control.

---

## SCENE 10 — OUTRO (0:15)

**Visual:** PortShim title, links to Quick Start and Checklist videos

That's the Phase-by-Phase Decision Guide. Watch the Quick Start for the step-by-step walkthrough, and the Pre-Engagement Checklist video to prepare before your first engagement.

Documentation and links in the description.

---

---

## SCENE OUTRO — END CARD (0:15)
**Visual:** PortShim title fades back in. GitHub URL centred below: github.com/ozdemir-mehmet/portshim. Red accent bar fades in at top.
**Audio:** (Narration over gentle background music)

That concludes Phase-by-Phase Decision Guide. Full documentation, printable checklists, and all source code are available at the GitHub repository linked below.

PortShim is open source under the MIT licence. Contributions and feedback are welcome.

(Brief musical fade-out)

---


## PRODUCTION NOTES

- Total estimated duration: ~12-13 minutes
- Slide count target: 10 scenes
- Key visuals: Gate mockups showing sample output, decision matrix animation
- Code blocks: Minimal — this is concept-driven, not command-driven
- Transition: Use the pipeline flow diagram as a recurring visual anchor between gates

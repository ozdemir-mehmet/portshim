# Video Script: Pre-Engagement Checklist
# Source: references/operator-guide/03-pre-engagement-checklist.md
# Duration target: ~8 minutes
# Narrator: Professional, calm, instructive

---

## SCENE 1 — INTRO (0:10)
**Visual:** PortShim title card fading in on dark background. "On-Site Security Assessment Pipeline" subtitle appears below. Red accent bar animates across the bottom.
**Audio:** (Brief musical sting — 2 seconds — then fade to narration)

PortShim. On-site security assessment — automated, operator-controlled, and ready to deploy.

This is the Pre-Engagement Checklist.

---

## SCENE 2 — INTRODUCTION (0:25)

Before you run a single command, before you even connect to the target network, there are things you need to have in place. This checklist covers everything — authorisation, hardware, software, target information, and post-engagement planning.

Complete this before every engagement. Every single one.

---

## SCENE 3 — AUTHORISATION (1:15)

**Visual:** Authorisation letter template with highlighted fields

This is item one for a reason. Without it, nothing else matters.

You need a signed authorisation letter from the network owner or an authorised representative. Not verbal approval. Not an email saying "yeah go ahead." A signed document.

The letter must specify five things.

First — the target IP ranges. CIDR blocks, not vague descriptions. "Ten dot zero dot zero dot zero slash twenty-two," not "the office network."

Second — wireless SSIDs, if wireless testing is in scope. The specific network names you're authorised to test.

Third — the testing window. Start date and time, end date and time. This protects you. If something breaks at 3 AM on a Sunday and your window was Monday to Friday, you're covered.

Fourth — the physical testing location. Which meeting room? Which network port? If you're in a server room, make sure facilities knows.

Fifth — a point of contact. Name, phone number, email. Someone who can make decisions if something unexpected happens.

Also document what's out of scope. Printers. VoIP phones. Industrial control systems. Medical devices. If it shouldn't be touched, write it down.

And establish an emergency stop procedure. Who do you call if something breaks? How do you halt testing immediately?

The red warning on the checklist says it plainly — never begin without the signed letter. No authorisation equals no testing. Period.

---

## SCENE 4 — HARDWARE (1:00)

**Visual:** Laptop, Ethernet cable, external Wi-Fi adapter laid out on a desk

Hardware is straightforward but often overlooked.

You need a Linux laptop. Ubuntu 22.04 or later, Fedora 38 or later, Debian 12. Any modern distro. Bring your power adapter — you might be in a server room or a meeting room without convenient outlets.

Bring an Ethernet cable. Cat5e or better, at least three metres. If your laptop doesn't have a native RJ45 port, bring a USB-to-Ethernet adapter.

Now, wireless testing. If it's in scope, you need an external Wi-Fi adapter that supports monitor mode and packet injection. The Alfa AWUS036ACH is the standard — about thirty-five dollars, dual-band, reliable injection on every Linux distribution.

And critically — test it before you arrive on site. Plug it in, run airmon-ng start wlan0 to enable monitor mode, then run aireplay-ng dash dash test wlan0mon to verify injection works. If you show up without testing and the adapter doesn't work, the report will say "Wireless Assessment Partial."

If budget allows, bring a spare. A single thirty-five-dollar card is your entire wireless capability.

---

## SCENE 5 — SOFTWARE (0:45)

**Visual:** Terminal showing git pull, sync, and nuclei update commands

Software preparation takes about two minutes.

First, pull the latest PortShim code — git pull in the project directory.

Second, sync knowledge — python scripts slash sync underscore knowledge dot py dash dash all. This pulls the latest CVE data from seven tracked repositories.

Third, check freshness — python scripts slash check dash skill dash freshness dot py. This warns you if any source is more than thirty days stale.

Fourth, update Nuclei templates — nuclei dash update dash templates. Nuclei is the deep vulnerability scanner, and stale templates mean missed findings.

Fifth, verify Hermes is working — hermes doctor. All green? You're good.

Sixth and seventh — select your stealth profile and LLM mode. We covered those in the Quick Start video. For most engagements, it's Surgical plus Hybrid.

---

## SCENE 6 — TARGET INFORMATION (1:00)

**Visual:** Fillable worksheet appearing section by section

Gather as much information as you can before arriving on site. The more you know, the fewer surprises.

Fill out the target IP range. If you don't know the exact CIDR, ask. Scanning the wrong subnet wastes time and risks scanning systems outside your authorisation.

Note the wireless SSIDs if wireless is in scope.

List known exclusions — printers, VoIP phones, building management systems, anything the client has specifically said to avoid.

Note the network type if you know it — is it a flat single subnet, or segmented with VLANs? If you don't know, that's fine. The pipeline will discover this.

Flag whether wireless is in scope. It defaults to no.

Note any known technologies — Windows Active Directory, Exchange, MSSQL, Linux servers, cloud infrastructure. This helps prioritise scanning.

Is there an intrusion detection or prevention system? If yes, use Silent Entry. If unknown, start with Surgical.

Is there network access control — 802.1X? If yes, you'll need a port that's been configured for access, or a NAC bypass strategy.

Expected host count — even a rough estimate helps you spot anomalies. If you expect fifty hosts and find eight hundred, something's off.

And the physical location — meeting room, server room, IDF closet. Know where you're going.

---

## SCENE 7 — STEALTH AND LLM DECISIONS (0:35)

**Visual:** Decision tables from the guide

Two quick decision tables.

For stealth — if intrusion detection is active, use Silent Entry. Slow, quiet, single-threaded. For a standard assessment with no known monitoring, use Surgical. Balanced, rate-limited, the default. For time-critical situations where full coverage matters more than noise, use Full Assault.

You can change profiles between phases. Start with Surgical for reconnaissance, then switch to Silent Entry for exploitation if the client has monitoring.

For LLM mode — if the site is air-gapped with no internet, use Local. Everything runs on your laptop's GPU. If you have a field laptop with a decent GPU, use Hybrid. Exploitation stays local, reports use the cloud. If you're on a thin client with no GPU, use Cloud. Everything goes through the API.

For most engagements, Hybrid is the right answer.

---

## SCENE 8 — POST-ENGAGEMENT (0:35)

**Visual:** Calendar with retest date, encrypted email icon, debrief meeting

Plan the exit before you enter.

How will you deliver the reports? Encrypted email, USB drive, secure portal? Agree on this before you have a forty-two-page document full of critical vulnerabilities sitting on your laptop.

Understand the data retention policy — how long do you keep scan data and findings? After delivery, you're holding sensitive information about the client's security posture. Know when to delete it.

Schedule the retest window. When will the client have fixes ready for Phase 5? Thirty days? Sixty? Put it in the calendar now.

And schedule the debrief meeting with client stakeholders. The executive brief is good, but a twenty-minute call walking through the top findings is better.

---

## SCENE 9 — ON-SITE PRE-FLIGHT (0:40)

**Visual:** Four terminal commands with checkmarks

Before you tell Hermes to start, run these four checks on site.

One — am I actually on the target network? Ping the gateway. If you can't reach anything, you're on the wrong port or the wrong VLAN.

Two — do I have internet? Unless you're in fully local air-gapped mode, you need connectivity. A quick curl to api dot github dot com confirms it.

Three — is Hermes working? Her mes doctor. If anything is red, fix it before starting.

Four — wireless pre-flight, if wireless is in scope. Run lsusb to confirm the Alfa adapter is detected. Run airmon-ng start to enable monitor mode. Run aireplay-ng dash dash test to verify injection. All three green? You're ready for a full wireless assessment.

All checks passed? Load the skill and start.

Forward slash skill space site dash assessment dash pipeline.

---

## SCENE 10 — EMERGENCY CONTACTS (0:20)

**Visual:** Contact card template

Fill out your emergency contacts before you begin.

Your site contact — the person who can get you into locked rooms or explain unusual network behaviour.

Your escalation contact — the person you call if something breaks. This is not the time to scroll through your phone looking for a number.

And your team lead — someone who knows you're on an engagement and can back you up if needed.

---

## SCENE 11 — OUTRO (0:20)

**Visual:** The full checklist on screen, checkmarks animating down the list

That's the pre-engagement checklist. Authorisation first, always. Hardware tested before you leave. Software updated. Target information gathered. Stealth and LLM modes chosen. Post-engagement planned. On-site checks verified. Emergency contacts filled in.

Complete this before every engagement. It takes ten minutes and it saves you from the mistakes that happen when you skip preparation.

Watch the Quick Start video next for the step-by-step walkthrough of running an actual engagement.

Documentation and a printable version of the checklist are linked in the description.

---

---

## SCENE OUTRO — END CARD (0:15)
**Visual:** PortShim title fades back in. GitHub URL centred below: github.com/ozdemir-mehmet/portshim. Red accent bar fades in at top.
**Audio:** (Narration over gentle background music)

That concludes Pre-Engagement Checklist. Full documentation, printable checklists, and all source code are available at the GitHub repository linked below.

PortShim is open source under the MIT licence. Contributions and feedback are welcome.

(Brief musical fade-out)

---


## PRODUCTION NOTES

- Total estimated duration: ~7-8 minutes
- Slide count target: 11 scenes
- Key visual: The checklist itself — animate checkmarks appearing as each section is covered
- Tone: Slightly more procedural than the other two videos — this is a preparation guide
- Props: Show the physical hardware (Alfa card, Ethernet cable, laptop) in the hardware section if possible

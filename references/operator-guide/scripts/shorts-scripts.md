# YouTube Shorts — PortShim Operator Tips
# Source: Operator's Quick Start + Phase Decision Guide
# Format: Portrait 1080×1920, ≤60 seconds each
# Style: Fast cuts, bold text overlays, attention-grabbing hooks

---

## SHORT 1: What Is PortShim? (0:30)

**Hook (first 2 seconds):**
PortShim. Wall jack to domain admin in 27 minutes.

**Visual sequence:**
- Dark bg → PORTSHIM title slam
- Quick cut: laptop plugging into wall port
- Pipeline flow diagram (compressed, fast)
- Text overlay: "6 PHASES. OPERATOR IN CONTROL."

**Narration:**
PortShim is an on-site security assessment pipeline. You plug in a laptop. It maps the network. Finds every vulnerability. Exploits the critical ones. Generates your report. And tracks fixes across retests. All with you making the decisions at review gates between every phase.

**End card:**
github.com/ozdemir-mehmet/portshim

---

## SHORT 2: One Command to Deploy (0:25)

**Hook (first 2 seconds):**
One command. That's it.

**Visual sequence:**
- Terminal typing: `python deploy.py`
- Progress bar or checklist animating
- Text popups: "nmap ✓" "nuclei ✓" "25 skills ✓"
- Thumbs up

**Narration:**
Clone the repo. Run deploy dot py. That one command detects your Linux distribution, installs every tool, pulls twenty-five cybersecurity skills, and configures everything. Two minutes and you're ready to assess.

**Text overlay:**
`git clone → python deploy.py → done`

---

## SHORT 3: The Four Decisions at Every Gate (0:35)

**Hook (first 2 seconds):**
At every gate, you have four options. Know them.

**Visual sequence:**
- 4 cards animating in from corners
- APPROVE (green) → RERUN (blue) → MODIFY SCOPE (yellow) → ABORT (red)
- Each card pulses with its colour

**Narration:**
Between every phase, PortShim stops and waits for you. APPROVE — output looks good, proceed. RERUN — something's off, repeat with different settings. MODIFY SCOPE — adjust your target range, add wireless, change stealth. ABORT — stop everything immediately. The pipeline never auto-advances. You're always in control.

**End card:**
OPERATOR IN CONTROL

---

## SHORT 4: The Pipeline in 45 Seconds (0:45)

**Hook (first 2 seconds):**
Six phases. Five gates. One operator.

**Visual sequence:**
- Fast animated pipeline flow
- Phase 0: SETUP → laptop icon
- Gate 0: checkmark
- Phase 1: RECON → radar/map icon
- Gate 1: checkmark
- Phase 2: VULN → bug/target icon
- Gate 2: warning SELECT TARGETS
- Phase 3: EXPLOIT → lock broken icon
- Gate 3: checkmark
- Phase 4: REPORT → document icon
- Gate 4: checkmark
- Phase 5: RETEST → cycle icon

**Narration:**
Phase zero — bootstrap and confirm scope. Phase one — discover every host, classify every device. Phase two — cross-reference CVEs, score by severity. Gate two is critical — you select exactly which targets get exploited. Phase three — verify exploits, escalate, move laterally. Phase four — generate the Word report, PowerPoint brief, and Excel checklist. Phase five — retest after remediation, classify every fix. Six phases, five gates, one operator. You.

---

## SHORT 5: The Three Deliverables (0:25)

**Hook (first 2 seconds):**
Three files. Every stakeholder covered.

**Visual sequence:**
- Three file icons slide in
- .docx → "Technical Report — for engineers"
- .pptx → "Executive Brief — for the CISO"
- .xlsx → "Remediation Checklist — for the PM"
- Colour-coded severity indicators

**Narration:**
After the assessment, you get three deliverables. The technical Word document — every finding with CVSS scores and step-by-step remediation. The executive PowerPoint brief — risk summary for management. And the Excel checklist — colour-coded by severity, with tick columns for tracking fixes. One for engineers. One for the CISO. One for the project manager.

---

## SHORT 6: Wireless Pre-Flight Check (0:30)

**Hook (first 2 seconds):**
Don't show up without the right hardware.

**Visual sequence:**
- Laptop → internal Wi-Fi icon with X
- External Alfa adapter plugging in → checkmark
- Terminal: `airmon-ng start` → MONITOR OK
- Terminal: `aireplay-ng --test` → INJECTION OK
- Report snippet: "WIRELESS-HARDWARE-MISSING" with red highlight

**Narration:**
If wireless testing is in scope, your internal laptop Wi-Fi won't cut it. No monitor mode. No packet injection. PortShim's pre-flight check tests your hardware before scanning. Without an external adapter — like the thirty-five-dollar Alfa AWUS036ACH — the report will say Wireless Assessment Incomplete. Bring the right card. Test it before you arrive. Your report depends on it.

---

## SHORT 7: Authorisation First (0:20)

**Hook (first 2 seconds):**
No signed letter. No testing. Period.

**Visual sequence:**
- Red warning triangle
- Document icon with signature line
- Text overlay: "IP RANGE. TESTING WINDOW. POINT OF CONTACT."
- Green checkmark

**Narration:**
Before you run a single command — signed authorisation. Not an email. Not a verbal okay. A document that specifies the target IP range, the testing window, and an emergency contact. No authorisation equals no testing. That's not a guideline. That's the rule.

---

## PRODUCTION NOTES

- All shorts: 1080×1920 portrait
- Fast cuts — hold no shot longer than 3 seconds
- Text overlays: bold, red (#CC4141) accent colour, dark background (#18181C)
- Music: same BenSound track, shortened to fit
- Voice: Kokoro bf_isabella
- End card on every short: github.com/ozdemir-mehmet/portshim

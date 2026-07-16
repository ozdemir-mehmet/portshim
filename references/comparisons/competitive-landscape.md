# PortShim vs the Field — Competitive Landscape

> Comparison of PortShim against the top automated pentesting frameworks on GitHub.  
> Sorted by GitHub stars. All projects active as of July 2026.

---

## The Contenders

| # | Project | ★ Stars | 🍴 Forks | Lang | AI/LLM? | Zero Human? |
|---|---|---|---|---|---|---|
| 1 | **PentestGPT** | 14,036 | 2,444 | Python | ✅ GPT/OpenAI | ❌ Human-in-loop |
| 2 | **ReconSpider** | 2,719 | 365 | Python | ❌ | ✅ Automated |
| 3 | **RedAmon** | 2,091 | 441 | Python | ✅ LLM agents | ✅ Claimed |
| 4 | **Guardian CLI** | 1,715 | 354 | Python | ✅ Gemini | ❌ Interactive |
| 5 | **AutoPentestX** | 1,237 | 238 | Python | ❌ | ✅ Automated |
| 6 | **AutoPWN-Suite** | 1,089 | 137 | Python | ❌ | ✅ Automated |
| 7 | **AIRecon** | 778 | 127 | Python | ✅ Ollama (local) | ✅ Claimed |
| 8 | **PortShim** | — | — | Python | ✅ Multi-LLM | ❌ Operator-gated |

---

## Deep Dive — Top Competitors

### PentestGPT (14K ★)

| What | Detail |
|---|---|
| **Approach** | LLM-powered agentic framework. GPT reasons about test steps, calls tools, interprets results. |
| **Model** | GPT-4/OpenAI (cloud). Planning to support local models. |
| **Phases** | Recon → Scanning → Vulnerability Analysis → Exploitation → Reporting (LLM-driven, not hardcoded). |
| **Human control** | Human-in-the-loop — operator reviews and approves actions. |
| **Strengths** | Huge community. Flexible reasoning (LLM adapts to situation). Well-documented. |
| **Weaknesses** | Cloud-dependent (OpenAI API key). No stealth profiles. No wireless. No retest. No operator docs. |

### RedAmon (2.1K ★)

| What | Detail |
|---|---|
| **Approach** | AI-powered agentic red team. Claims "zero human intervention" — fully autonomous from recon to post-exploitation. |
| **Model** | LLM agents (configurable provider). |
| **Phases** | Recon → Exploitation → Post-exploitation (agent-orchestrated). |
| **Human control** | None by design. "Zero human intervention." |
| **Strengths** | Bold ambition. Multi-agent architecture. Post-exploitation coverage. |
| **Weaknesses** | No human gates — dangerous for production. No stealth. No wireless. No retest. No docs. Aggressive marketing. |

### AIRecon (778 ★)

| What | Detail |
|---|---|
| **Approach** | Autonomous agent with Ollama (local LLM) + Kali Linux Docker sandbox + Textual TUI. |
| **Model** | Ollama — fully local, no API keys, no cloud. |
| **Phases** | Recon → Scanning → Exploitation (agent-driven). |
| **Human control** | TUI interface — operator can observe and intervene. |
| **Strengths** | Fully offline. No API costs. Docker sandbox for safety. Nice TUI. |
| **Weaknesses** | Small community. Quality depends on local model. No wireless. No retest. No reporting beyond terminal output. |

### AutoPWN-Suite (1K ★)

| What | Detail |
|---|---|
| **Approach** | Automated vulnerability scanning + exploitation. nmap → vuln scan → exploit. |
| **Model** | None — traditional toolchain. |
| **Phases** | Scan → Exploit (linear, no gates). |
| **Human control** | CLI flags only. |
| **Strengths** | Simple. Fast. Self-contained. |
| **Weaknesses** | No AI. No stealth. No wireless. No retest. No report generation. Basic. |

---

## Feature Matrix

| Feature | PentestGPT | RedAmon | AIRecon | AutoPentestX | AutoPWN | **PortShim** |
|---|---|---|---|---|---|---|
| **Network-wide (CIDR)** | ✅ | ❓ | ❓ | ❌ | ❌ | ✅ |
| **Device classification** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 40+ roles |
| **Stealth profiles** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 3 profiles |
| **Operator review gates** | ⚠️ Partial | ❌ | ⚠️ TUI | ❌ | ❌ | ✅ 6 gates |
| **LLM-powered exploitation** | ✅ Cloud | ✅ Cloud | ✅ Local | ❌ | ❌ | ✅ Multi-engine |
| **Multi-model (local+cloud)** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 3 modes |
| **Wireless testing** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Retest phase** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Multi-format reports** | ❌ | ❌ | ❌ | PDF only | ❌ | ✅ docx+pptx+xlsx |
| **Remediation tracking** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ xlsx checklist |
| **Knowledge-source tracking** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Commit-pinned |
| **Operator documentation** | ❌ | ❌ | ❌ | Minimal | ❌ | ✅ 4-doc suite |
| **Distro-agnostic deploy** | ❌ | ❌ | ✅ Docker | ❌ | ❌ | ✅ apt/dnf/pacman/... |
| **Offline capable** | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ Local mode |

---

## Radar Chart Summary

### PentestGPT
**Best for:** Teams with OpenAI access who want flexible, LLM-driven testing.  
**Missing:** Stealth, wireless, retesting, operator docs.  
**Risk:** Cloud dependency. No offline mode. OpenAI API costs.

### RedAmon
**Best for:** Fully autonomous red teaming — if you trust the AI completely.  
**Missing:** Everything PortShim has.  
**Risk:** Zero human gates. "Zero human intervention" is a liability, not a feature.

### AIRecon
**Best for:** Privacy-conscious testers who want fully local AI with a nice TUI.  
**Missing:** Wireless, retest, reports. Small community.  
**Risk:** Quality depends entirely on local Ollama model quality.

### AutoPentestX / AutoPWN-Suite
**Best for:** Quick, simple, no-AI automated scanning.  
**Missing:** Everything beyond basic scan→exploit.  
**Risk:** Limited scope. No reporting beyond PDF/text.

### PortShim
**Best for:** Professional engagements requiring control, coverage, and client-ready deliverables.  
**Missing:** Community size (private). Docker sandbox (parked — wireless breaks in containers).  
**Risk:** Hermes dependency. LLM quality dependence in exploitation phase (mitigated by benchmarks).

---

## Unique Advantages of PortShim

| Advantage | No Other Tool Has This |
|---|---|
| **Operator review gates between every phase** | Only PentestGPT has partial human-in-loop. No one else gates exploitation with explicit target approval. |
| **Stealth profiles (3 levels)** | No other tool has IDS-aware timing controls. |
| **Wireless testing** | Only PortShim supports Wi-Fi pentesting + hardware pre-flight check. |
| **Retest phase with auto-classification** | FIXED/STILL OPEN/NEW/REGRESSION. No other tool tracks remediation. |
| **Multi-stakeholder reporting** | .docx (technical) + .pptx (executive) + .xlsx (tracking). Others output PDF or plain text only. |
| **Operator documentation suite** | Quick Start, Decision Guide, Checklist, Red Team Playbook. Designed for non-red-team operators. |
| **Knowledge-source tracking** | Commit-pinned external repos with staleness detection. No other tool has this. |
| **Distro-agnostic deployment** | Single `deploy.py` detects and adapts to apt/dnf/pacman/zypper/apk. |
| **Hybrid LLM mode** | Local for exploitation (uncensored, air-gap) + cloud for reports. No other tool splits workloads. |
| **One-command start** | `portshim scan 10.0.0.0/22` — all pre-flight in one step. No other tool wraps 5 steps. |
| **Cross-engagement analytics** | SQLite scan history with query/compare/stats. No other tool tracks findings across engagements. |
| **Benchmark-driven model selection** | Tested 4 models against 4 phases. Per-phase auto-selection. No other tool benchmarks before configuring. |

---

## Gaps to Close

| Gap | Who Has It | Priority | Status |
|---|---|---|---|
| **Community / visibility** | PentestGPT (14K ★) | Medium | Private repo — parked |
| **Docker/Kali sandbox** | AIRecon has clean Docker isolation | Low | Parked (#3). Wireless breaks in Docker. |
| ~~SQLite persistence / scan history~~ | ~~AutoPentestX~~ | — | ✅ **Done.** `scripts/scan_db.py` + auto-save on Phase 4+5. |
| ~~Ease of first run~~ | ~~AutoPentestX (1 command)~~ | — | ✅ **Done.** `portshim scan 10.0.0.0/22` wrapper. |
| ~~LLM model selection~~ | ~~None — everyone hardcodes models~~ | — | ✅ **Done.** Benchmark matrix + per-phase `llm-config.py`. |
| **Fully autonomous mode** | RedAmon claims zero-human | Low | Operator gates are a feature, not a bug. |

---

## What Changed Since Initial Evaluation (July 2026)

| Improvement | Before | After |
|---|---|---|
| **Ease of first run** | 5 manual steps (deploy→sync→stealth→LLM→skill) | `portshim scan 10.0.0.0/22 --stealth surgical --mode hybrid` |
| **Scan history** | JSON files only, no cross-engagement queries | SQLite DB, auto-save, query-db.py with stats/compare/export |
| **LLM model selection** | Hardcoded "hauhauCS for exploit, DeepSeek for reports" | Benchmark matrix across 4 models, per-phase auto-selection |
| **LLM exploitation guidance** | No documented model performance | Benchmark shows Qwen3-Coder + SuperGemma4 outperform "uncensored" models |

---

## Recommendation

PortShim competes on **control, coverage, and deliverables** — not on simplicity or community size. For professional engagements where an operator needs to make decisions, cover wireless, track remediation, and produce client-ready reports, no other tool matches the full feature set.

For quick single-host scans or learning, AutoPentestX or AIRecon are lighter-weight alternatives. For LLM-driven flexibility, PentestGPT has the community but lacks the controls PortShim provides.

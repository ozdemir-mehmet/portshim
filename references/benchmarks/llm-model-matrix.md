# LLM Model Benchmark Matrix

> Generated: 2026-07-01  
> Method: 4 representative prompts per pipeline phase, scored against pass criteria  
> ✅ PASS = 80%+ criteria met | ⚠️ PARTIAL = 40-79% | ❌ FAIL = <40% or refusal

---

## Results

| Model | Size | Phase 1 Recon | Phase 2 CVE | Phase 3 Exploit | Phase 4 Report |
|---|---|---|---|---|---|
| **Qwen3-Coder 30B** | 17.8 GB | ✅ PASS | ✅ PASS | ✅ PASS | ✅ PASS |
| **SuperGemma4 26B** | 16.0 GB | ✅ PASS | ✅ PASS | ✅ PASS | ✅ PASS |
| **HauhauCS 35B** | 20.2 GB | ✅ PASS | ✅ PASS | ⚠️ PARTIAL | ✅ PASS |
| **DeepSeek V4 Pro** | Cloud | ✅ PASS | ✅ PASS | ⚠️ PARTIAL | ✅ PASS |
| **Llama-4-Scout 17B (16E)** | 61.0 GB | ⚠️ PARTIAL | ✅ PASS | ⚠️ PARTIAL | ✅ PASS |

## Recommended Per-Phase Configuration

### Fully Local (Air-Gap)

| Phase | Model | Rationale |
|---|---|---|
| **1 — Recon** | Any local model | nmap XML parsing is deterministic. Smallest model works. |
| **2 — CVE Analysis** | Qwen3-Coder or SuperGemma4 | Good reasoning, faster than HauhauCS. |
| **3 — Exploitation** | Qwen3-Coder or SuperGemma4 | Both passed fully. HauhauCS surprisingly weaker on exploit reasoning despite "uncensored" label. |
| **4 — Reporting** | SuperGemma4 or HauhauCS | Good narrative quality. Qwen3-Coder acceptable but slightly less polished. |

### Hybrid (Recommended)

| Phase | Model | Rationale |
|---|---|---|
| **1 — Recon** | Any local | Fast, no API cost. |
| **2 — CVE Analysis** | DeepSeek V4 | Best CVE knowledge, always current. |
| **3 — Exploitation** | Qwen3-Coder (local) | DeepSeek refuses specific exploit commands. Local uncensored models don't. |
| **4 — Reporting** | DeepSeek V4 | Best narrative quality, professional tone. |

### Fully Cloud

| Phase | Model | Notes |
|---|---|---|
| **1 — Recon** | DeepSeek V4 | Fine. |
| **2 — CVE Analysis** | DeepSeek V4 | Best choice. |
| **3 — Exploitation** | DeepSeek V4 | ⚠️ Will refuse specific exploit commands. Use for planning only, not execution. |
| **4 — Reporting** | DeepSeek V4 | Best choice. |

---

## Key Findings

### 1. "Uncensored" doesn't mean "better at exploits"
HauhauCS is labeled "aggressive uncensored" but scored PARTIAL on exploit reasoning — it missed providing specific tool commands (Metasploit module names, exact flags). Qwen3-Coder and SuperGemma4, despite being coding/general models, provided complete exploitation guidance.

### 2. Cloud models refuse specifics
DeepSeek V4 scored PARTIAL on Phase 3 — it described the attack conceptually but refused to provide Metasploit commands or specific exploitation steps. This is a policy restriction, not a capability gap.

### 3. Phase 1 & 2 are commodity tasks
Every model passed reconnaissance parsing and CVE correlation. These phases don't need a powerful model — any 7B+ model would work. The current 26-35B models are overkill for nmap XML parsing.

### 4. Report quality varies
DeepSeek produces the most polished reports. SuperGemma4 is close behind. Qwen3-Coder is functional but less narrative. HauhauCS sometimes adds unnecessary "attitude."

### 5. Model size vs quality
SuperGemma4 at 16GB outperformed HauhauCS at 20GB on exploit reasoning. Smaller model, better results. Architecture matters more than parameter count.

---

## Re-Benchmarking

To re-run benchmarks after adding new models:

```bash
# Set model directory (configurable)
export PD_MODELS_DIR=C:/LocalModels

# Cloud only
python scripts/benchmark-models.py --cloud-only

# Local only
python scripts/benchmark-models.py --local-only

# Specific model
python scripts/benchmark-models.py --model "Qwen3-Coder"

# Specific phases only
python scripts/benchmark-models.py --phases 3
```

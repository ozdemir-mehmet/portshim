<div align="center">
  <img src="logo.svg" width="240" alt="PortShim">
  <h1 align="center">PortShim</h1>
  <p align="center">
    <strong>Picking the network, one port at a time.</strong>
  </p>
  <p align="center">
    An on-site pentest pipeline for authorised security professionals.<br>
    Air-gapped · LLM-powered · No trace left behind.
  </p>
  <p align="center">
    <a href="https://ozdemir-mehmet.github.io/portshim/">Website</a>
    ·
    <a href="#quick-start">Quick Start</a>
    ·
    <a href="#benchmarks">Benchmarks</a>
    ·
    <a href="#license">License</a>
  </p>
</div>

<br>

## Overview

PortShim is a **6-phase penetration testing pipeline** designed for on-site, air-gapped operations. Instead of relying on cloud LLMs, it runs fully on a local GPU via llama.cpp, with per-phase model selection so you're never using a slow model for a fast task — and never using a censored model for an exploit phase.

The name is a double entendre: in lockpicking, a *shim* is a thin tool that bypasses wafer locks; in networking, a shim sits between layers to intercept or modify traffic. **PortShim picks the network.**

## The 6 Phases

| # | Phase | Model | Purpose |
|---|-------|-------|---------|
| 1 | Reconnaissance | Any small model | Parse nmap/masscan output |
| 2 | CVE Correlation | Qwen3-Coder 30B | Match services to CVEs |
| 3 | Exploitation | hauhauCS-aggressive | Generate exploit chains & PoCs |
| 4 | Post-Exploitation | hauhauCS-aggressive | Lateral movement & privesc |
| 5 | Reporting | SuperGemma4 26B | Client-ready reports |
| 6 | Playbook Generation | Cloud or local | Operator playbook |

## Requirements

- **GPU:** AMD Radeon 8060S / NVIDIA RTX 3090+ (24 GB VRAM)
- **RAM:** 64 GB recommended
- **Storage:** 50 GB+ free for models
- **Engine:** llama.cpp b9827+ (Vulkan or CUDA)
- **Python:** 3.11+

## Quick Start

```bash
# Start the server
llama-server -m C:/LocalModels/hauhauCS/...Q4_K_M.gguf \
  --port 8080 --ctx-size 32768 -ngl 99 --host 127.0.0.1

# Verify it's running
curl http://127.0.0.1:8080/v1/models

# Run the full pipeline
python run_pipeline.py --target 10.0.1.0/24
```

## Benchmarks

| Model | Tok/s | Censor | Acc | Code | FX | Redteam |
|-------|-------|--------|-----|------|----|---------|
| **hauhauCS-aggressive** | 58.9 | 5/5 | 60% | 5/5 | 89% | **93.4%** |
| **supergemma4** | 48.7 | 5/5 | 60% | 3/5 | 98% | **88.4%** |
| **Qwen3-Coder** | 61.0 | 4/5 | 100% | 5/5 | 89% | **83.6%** |

All on AMD Radeon 8060S, llama.cpp Vulkan, 32K context, Q4_K_M quant.

## License

Apache 2.0 — use it, modify it, share it. Authorised security testing only.

---

<p align="center">
  <sub>Built with <a href="https://github.com/ggml-org/llama.cpp">llama.cpp</a> · Powered by Vulkan · Backed by benchmarks</sub>
</p>

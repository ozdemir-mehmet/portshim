# LLM Architecture

PortShim supports three deployment modes for LLM inference.

## Decision Matrix

| Component | Local Mode | Hybrid Mode | Cloud Mode |
|---|---|---|---|
| nmap, httpx, nuclei, subfinder | Local | Local | Local |
| nmap-vulners (Vulners API) | Local* | Local* | Local* |
| Guardian agent pipeline | Local | Local | Cloud |
| NeuroSploit agents | Local | Local | Cloud |
| Anthropic skill execution | Local | Cloud | Cloud |
| Hermes orchestrator | Local | Cloud | Cloud |
| Report generation | Local | Cloud | Cloud |
| Retest diff | Local | Local | Local |

\* Vulners API requires internet but only transmits service versions (not target data).

## Model Assignments

| Consumer | Local | Cloud |
|---|---|---|
| Guardian (pentesting) | hauhauCS-aggressive (uncensored, 59t/s) | deepseek-v4-pro |
| NeuroSploit | hauhauCS-aggressive / supergemma4 | deepseek-v4-pro |
| Anthropic skills | Qwen3-Coder-30B (instruction following) | deepseek-v4-pro |
| Hermes orchestrator | Qwen3-Coder-30B | deepseek-v4-pro |
| Report writing | Qwen3-Coder-30B | deepseek-v4-pro |
| Fallback | supergemma4-26b (49t/s, uncensored) | — |

## Security: What NEVER Uses Cloud

- Raw scan data (nmap XML, nuclei JSON) — stays on field machine
- Credential material (hashes, passwords) — never leaves field machine  
- Target IPs/hostnames — cloud only with explicit user opt-in
- `--offline` flag disables ALL cloud, including Vulners API (use cached data)

## Config Generation

```bash
python scripts/llm-config.py local --output-dir ./configs/   # Air-gapped
python scripts/llm-config.py hybrid --output-dir ./configs/   # Field laptop
python scripts/llm-config.py cloud --output-dir ./configs/    # Thin client
```

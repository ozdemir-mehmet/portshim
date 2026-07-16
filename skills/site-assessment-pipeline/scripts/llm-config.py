#!/usr/bin/env python3
"""
llm-config.py — Generate per-tool AND per-phase LLM configuration.

Based on benchmark results (references/benchmarks/llm-model-matrix.md).
Supports three deployment modes with automatic per-phase model selection.

Usage:
    python llm-config.py local              # Print configs to stdout
    python llm-config.py hybrid --output-dir ./configs/
    python llm-config.py cloud --export-env
    python llm-config.py --list             # List modes
    python llm-config.py --show-models      # Show available GGUF files
    python llm-config.py --models-dir ~/local-models  # Override model path

Environment:
    PD_MODELS_DIR    Path to .gguf model files (default: ~/local-models)

Per-phase model selection (from benchmark results):
  Phase 1 (Recon):  Any local model — nmap XML parsing is deterministic.
                    - Qwen3-Coder 30B (fastest, smallest) — DEFAULT
                    - SuperGemma4 26B or HauhauCS 35B also fine
  Phase 2 (CVE):    Qwen3-Coder or SuperGemma4 — good reasoning.
                    - Qwen3-Coder 30B — DEFAULT
                    - SuperGemma4 26B (alternative)
  Phase 3 (Exploit): Qwen3-Coder or SuperGemma4 — both PASS.
                     HauhauCS PARTIAL despite "uncensored" label.
                     - SuperGemma4 26B (uncensored, best exploit reasoning) — DEFAULT
                     - Qwen3-Coder 30B (also PASS, alternative)
  Phase 4 (Report): SuperGemma4 or HauhauCS — best narrative quality.
                    - SuperGemma4 26B (polished, professional) — DEFAULT
                    - HauhauCS 35B (acceptable, sometimes adds attitude)

Models available on this machine:
  - qwen3-coder-30b-a3b-instruct  -> ~/local-models/qwen3-coder-30b-a3b-instruct/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf
  - supergemma4-26b-uncensored    -> ~/local-models/supergemma4-26b-uncensored/supergemma4-26b-uncensored-fast-v2-Q4_K_M.gguf
  - hauhau-cs-35b-uncensored      -> ~/local-models/hauhau-cs-35b/Qwen3.5-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_S.gguf
"""

import argparse, json, os, sys
from pathlib import Path

MODEL_IDS = {
    "qwen3-coder-30b-a3b-instruct":  {"path": "qwen3-coder-30b-a3b-instruct",  "file": "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf"},
    "supergemma4-26b-uncensored":    {"path": "supergemma4-26b-uncensored",    "file": "supergemma4-26b-uncensored-fast-v2-Q4_K_M.gguf"},
    "hauhau-cs-35b-uncensored":      {"path": "hauhau-cs-35b",                "file": "Qwen3.5-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_S.gguf"},
}

BENCHMARK_RECOMMENDATIONS = {
    "recon": {
        "local": "qwen3-coder-30b-a3b-instruct",
        "cloud": "deepseek-v4-pro",
        "note": "Any model works. Qwen3-Coder 30B is fastest/smallest of the three."
    },
    "vuln": {
        "local": "qwen3-coder-30b-a3b-instruct",
        "cloud": "deepseek-v4-pro",
        "note": "Qwen3-Coder or SuperGemma4. CVE correlation needs good reasoning."
    },
    "exploit": {
        "local": "supergemma4-26b-uncensored",
        "cloud": "deepseek-v4-pro",
        "note": "Qwen3-Coder and SuperGemma4 both PASS. HauhauCS PARTIAL despite uncensored label."
    },
    "report": {
        "local": "supergemma4-26b-uncensored",
        "cloud": "deepseek-v4-pro",
        "note": "SuperGemma4 best narrative quality locally. HauhauCS acceptable alternative."
    },
}

LOCAL_BASE_URL = "http://127.0.0.1:8080/v1"

MODES = {
    "local": {
        "label": "Fully Local",
        "description": "Everything on field laptop GPU. Air-gap capable. Uses llama.cpp.",
        "phases": {
            "recon":   {"model": BENCHMARK_RECOMMENDATIONS["recon"]["local"],   "provider": "openai_compatible", "base_url": LOCAL_BASE_URL},
            "vuln":    {"model": BENCHMARK_RECOMMENDATIONS["vuln"]["local"],    "provider": "openai_compatible", "base_url": LOCAL_BASE_URL},
            "exploit": {"model": BENCHMARK_RECOMMENDATIONS["exploit"]["local"], "provider": "openai_compatible", "base_url": LOCAL_BASE_URL},
            "report":  {"model": BENCHMARK_RECOMMENDATIONS["report"]["local"],  "provider": "openai_compatible", "base_url": LOCAL_BASE_URL},
        },
    },
    "hybrid": {
        "label": "Hybrid",
        "description": "Tactical (recon, vuln, exploit) local. Strategic (reporting) cloud.",
        "phases": {
            "recon":   {"model": BENCHMARK_RECOMMENDATIONS["recon"]["local"],   "provider": "openai_compatible", "base_url": LOCAL_BASE_URL},
            "vuln":    {"model": BENCHMARK_RECOMMENDATIONS["vuln"]["local"],    "provider": "openai_compatible", "base_url": LOCAL_BASE_URL},
            "exploit": {"model": BENCHMARK_RECOMMENDATIONS["exploit"]["local"], "provider": "openai_compatible", "base_url": LOCAL_BASE_URL},
            "report":  {"model": BENCHMARK_RECOMMENDATIONS["report"]["cloud"],  "provider": "deepseek"},
        },
    },
    "cloud": {
        "label": "Fully Cloud",
        "description": "All LLM work via DeepSeek API. Note: exploitation guidance will be limited.",
        "phases": {
            "recon":   {"model": BENCHMARK_RECOMMENDATIONS["recon"]["cloud"],   "provider": "deepseek"},
            "vuln":    {"model": BENCHMARK_RECOMMENDATIONS["vuln"]["cloud"],    "provider": "deepseek"},
            "exploit": {"model": BENCHMARK_RECOMMENDATIONS["exploit"]["cloud"], "provider": "deepseek"},
            "report":  {"model": BENCHMARK_RECOMMENDATIONS["report"]["cloud"],  "provider": "deepseek"},
        },
    },
}


def generate_env(mode: str, config: dict) -> str:
    phases = config.get("phases", {})
    lines = [
        f"# PortShim LLM Config — {config['label']}",
        f"# Source: python llm-config.py {mode}",
        f"# {config['description']}",
        f"#",
        f"# Per-phase model selection based on benchmarks:",
        f"#   references/benchmarks/llm-model-matrix.md",
        "",
    ]
    for phase, pc in phases.items():
        note = BENCHMARK_RECOMMENDATIONS.get(phase, {}).get("note", "")
        lines.append(f"# Phase: {phase} — {note}")
        lines.append(f"export PORTSHIM_{phase.upper()}_MODEL='{pc['model']}'")
        lines.append(f"export PORTSHIM_{phase.upper()}_PROVIDER='{pc['provider']}'")
        if pc.get("base_url"):
            lines.append(f"export PORTSHIM_{phase.upper()}_BASE_URL='{pc['base_url']}'")
        lines.append("")
    return "\n".join(lines)


def main():
    default_models = os.environ.get("PD_MODELS_DIR", os.path.join(os.path.expanduser("~"), "local-models"))
    parser = argparse.ArgumentParser(description="Generate LLM configuration for PortShim")
    parser.add_argument("mode", nargs="?", help="Deployment mode: local, hybrid, cloud")
    parser.add_argument("--list", action="store_true", help="List available modes")
    parser.add_argument("--output-dir", default=None, help="Write config files to directory")
    parser.add_argument("--export-env", action="store_true", help="Export as shell env vars")
    parser.add_argument("--json", action="store_true", help="Output full config as JSON")
    parser.add_argument("--models-dir", default=default_models, help="Path to .gguf model files")
    parser.add_argument("--show-models", action="store_true", help="Show available models and GGUF files")
    args = parser.parse_args()

    if args.show_models:
        print("=== Available Models ===")
        models_dir = Path(args.models_dir)
        print(f"Models directory: {models_dir}")
        print()
        for mid, info in MODEL_IDS.items():
            gguf_path = models_dir / info["path"] / info["file"]
            exists = gguf_path.exists()
            size = f"{gguf_path.stat().st_size / (1024**3):.1f} GB" if exists else "NOT FOUND"
            print(f"  {mid}")
            print(f"    File: {info['file']}")
            print(f"    Path: {gguf_path}")
            print(f"    Status: {size}")
            print()
        sys.exit(0)

    if args.list:
        for name, cfg in MODES.items():
            print(f"  {name:<10} {cfg['label']}")
            print(f"            {cfg['description']}")
            print(f"            Phases: {', '.join(cfg['phases'].keys())}")
            print()
        sys.exit(0)

    if not args.mode:
        parser.print_help()
        sys.exit(1)

    if args.mode not in MODES:
        print(f"Unknown mode '{args.mode}'. Valid: {', '.join(MODES.keys())}", file=sys.stderr)
        sys.exit(1)

    config = MODES[args.mode]

    if args.json:
        print(json.dumps(config, indent=2))
        sys.exit(0)

    env_text = generate_env(args.mode, config)

    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        env_file = out / "portshim.env"
        with open(env_file, "w") as f:
            f.write(env_text)
        print(f"Config: {env_file}")
        print(f"Mode:   {config['label']}")
        print(f"Models: {args.models_dir}")
    else:
        print(f"# PortShim — {config['label']}")
        print(f"# Models directory: {args.models_dir}")
        print(f"# {config['description']}")
        print()
        print(env_text)


if __name__ == "__main__":
    main()

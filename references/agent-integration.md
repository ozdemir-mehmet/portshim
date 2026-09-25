# Agent integration

PortShim is a command-line harness. There is no server API, no plugin protocol and no
SDK: every step is a command, and the steps that produce something write it to a file, so
any agent that can run a shell command and read a file can drive an engagement end to end.
This document is that integration, start to finish.

It is written to be self-contained inside a release. Everything it tells you to run or
read is present in the tree you are holding.

## What is in the tree

- `portshim` — the entry point: `scan`, `wireless`, `server`, `discover`.
- `deploy.py` — distro-aware bootstrap for the external tools (apt, dnf, pacman, zypper, apk).
- `scripts/` — the pipeline and operator tooling the CLI calls: discovery, classification,
  topology, report generation, retest diffing, checklist and document builders, the model
  benchmark runner, and the scan-history database tools.
- `references/` — the harness documents: tool dependencies, the deployment manifest, the
  model and server architecture, and this file.

What is deliberately absent: engagement data, per-model benchmark results, operator
playbooks, and the internal skill tree. None of it is needed to run the harness, and the CLI
does not read any of it. One maintenance script (`scripts/check-skill-freshness.py`) scans a
skill tree that exists only in a development checkout, and prints "No skills found." when it
is absent.

## Prerequisites

Python 3 and the external tools. The full list, per distro, is in
`references/deployment-manifest.md`; `references/tool-dependencies.md` says which tool
covers which phase and which ones are optional.

Bootstrap them:

```bash
python3 deploy.py --dry-run      # show the commands for your distro, change nothing
python3 deploy.py                # run them
```

Useful flags: `--skip-go` (skip the Go-based tools), `--skip-nmap-vulners`, `--skip-skills`
(skip Anthropic's published cybersecurity skills, which are separate from this harness),
`--with-msf` (adds Metasploit, 1 GB+). `--dry-run` first is the right habit — it prints
exactly what would be installed.

Nothing else is required. The CLI runs on a stock Python 3; the report builders need the
Python packages listed in the deployment manifest.

## Running the harness by hand

```bash
python3 portshim scan 10.0.0.0/22                      # default: surgical profile, hybrid models
python3 portshim scan 10.0.0.0/22 --engagement silent-entry
python3 portshim scan 10.0.0.0/22 --dry-run            # print the plan, do not execute
python3 portshim discover                              # reachable VLANs and subnets
python3 portshim wireless scan --duration 30 --band 5  # RF survey
python3 portshim server start --model <id>             # local llama-server lifecycle
python3 portshim server status
```

`python3 portshim <command> --help` prints the flags for each. `--dry-run` on `scan` is
the safe way to see the whole sequence before anything touches the network.

## The integration contract

Three behaviours make the harness agent-drivable, and they are the whole contract:

1. **Commands are idempotent and inspectable.** `--dry-run` prints the plan; `server status`
   reports state; nothing needs a long-lived daemon except an optional local model server.
2. **Steps that produce a result write it to a file.** Discovery writes a network map, the
   pipeline writes findings, the report builders write documents — so an agent reads the
   artifact rather than parsing stdout. The read-only commands (`server status`, a `--dry-run`)
   are the exceptions and print their state directly.
3. **Exit codes are meaningful.** A non-zero exit means a step failed, so an agent can
   branch on it without interpreting prose.

Artifacts land under `outputs/` — the pipeline and the wireless tooling write there, and the
document and video builders default to `output/` beside it — and generated configuration
under `configs/`, both created
on demand and both excluded from version control. An agent should treat them as working
state and never as something to commit.

## Exposing it to an agent

`deploy.py` bootstraps the tools; it does not register the harness with your agent, and no
installer script ships to do that. The equivalent is two explicit steps — a shell alias so
the CLI is callable from anywhere, and one instruction file that tells the agent where to
look:

```bash
# 1. Make the CLI callable outside the repo root
cd /path/to/portshim
echo "alias portshim='python3 $(pwd)/portshim'" >> ~/.bashrc
source ~/.bashrc

# 2. Give the agent a pointer (path shown for Hermes; use the equivalent
#    instruction file for any other agent)
HERMES_SKILLS=~/.hermes/skills          # your agent's own config directory, not this repo
mkdir -p "$HERMES_SKILLS/portshim"
cat > "$HERMES_SKILLS/portshim/SKILL.md" <<'EOF'
---
name: portshim
description: Run a PortShim engagement — scan, wireless, server, discover.
---
The harness is at /path/to/portshim. Read references/agent-integration.md there,
then drive it with the portshim CLI. Use --dry-run before any live scan.
EOF
```

For an agent with no instruction-file mechanism, the same integration is a paragraph of
system context: the repository path, the entry point, the `--dry-run` convention, and the
fact that results appear under `outputs/` and `output/`.

## A worked session

What you say to the agent, and what it runs:

> Target 10.0.0.0/22. Profile: surgical. Wireless in scope. Start with a plan, then run it.

```bash
python3 portshim discover --fast            # what is reachable at all
python3 portshim scan 10.0.0.0/22 --dry-run # print the engagement plan
python3 portshim scan 10.0.0.0/22 --engagement surgical   # execute
python3 portshim server status               # if the plan uses a local model
```

The agent's job is to read the artifacts each command writes, decide whether the next step
is warranted, and report the target state back to you. Autonomy belongs at that level —
choosing the next command — not in skipping `--dry-run` or in re-running a failed scan
without reading the error.

## Verifying the installation

```bash
python3 portshim --help                      # CLI resolves
python3 portshim server status               # reports whether a local model server is up
python3 portshim discover --fast             # exercises the network path read-only
python3 deploy.py --dry-run                  # re-checks the external tool plan
```

If `--help` works but a command fails immediately, the cause is almost always a missing
external tool rather than the harness: run `deploy.py --dry-run` and compare it against what
is installed.

## Where to go next

- `references/deployment-manifest.md` — per-distro install commands and verification.
- `references/tool-dependencies.md` — every external tool, its phase, whether it is required.
- `references/llm-architecture.md` — the deployment modes and which component runs where.

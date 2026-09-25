# External Tool Dependencies

PortShim shells out to established security tooling rather than reimplementing it. This
document is the authoritative list: what each tool is, which pipeline phase uses it, whether
it is required, how it is installed, and what happens when it is absent.

**Verified against the tree on 2026-09-21** (private repo). The inventory of *installed*
tools is derived from `deploy.py` — `PACKAGE_MAP`, `GO_TOOLS`, `PIP_PACKAGES` — and the
"used by" column from the code that actually invokes each binary. If you add a tool to
`deploy.py`, add it here; if you remove an invocation, correct this file.

## How to read the tables

Tags mark how a tool is driven. A row carrying **no** tag is invoked directly by PortShim's own
code — the core pipeline table is entirely runtime, so none of its rows are tagged. A table in
a section that is itself dedicated to agent-driven tools carries no per-row tag either.

| Tag | Meaning |
|---|---|
| **Agent** | Installed and configured, but run by the Hermes agent following its skill instructions — no code invocation exists |
| **Optional** | Needed only for one mode or module |

The "If missing" column states the real consequence. Where the impact varies it is graded —
**Hard stop** (the phase cannot run at all), **Degrades** (the phase runs with less coverage
or falls back), or **No effect** (nothing in the pipeline changes). Where an entire module
depends on the tool, the cell names what stops working.

"Used by" cites the file that invokes the tool, not a file that merely mentions it.

## Core pipeline

| Tool | What it is | Used by | Why | If missing |
|---|---|---|---|---|
| `nmap` | Port scanner and NSE script host | `scripts/network_scan.py` (`-sn` ping sweep), `scripts/discover.py` (subnet sweep, `-sV` service detection), `scripts/generate-findings.py` (parses `-oX` XML), `portshim` preflight | Host discovery, service/version fingerprinting, and the CVE input for Phase 2 | **Hard stop** — discovery and CVE extraction have no substitute |
| `ip` (iproute2) | Interface and routing table inspection | `scripts/discover.py` — `ip -4 -o addr show`, `ip -4 route show default` | Determines local subnets and the default gateway before sweeping | **Degrades** — subnet discovery degrades; gateways go unidentified |
| `curl` | HTTP client | `scripts/discover.py` (per host:port banner and fingerprint probes), `portshim` (URL reachability check) | HTTP fingerprinting and target validation | **Degrades** — HTTP probing is skipped |
| `python3` ≥ 3.10 | Runtime | Everything | — | **Hard stop**. PEP 668 distros require a venv — see `deployment-manifest.md` |
| `git` | VCS | `deploy.py` (clones the nmap-vulners NSE script) | Fetching the NSE script; also required to clone PortShim itself | **Degrades** — nmap-vulners install unavailable |
| `masscan` | Async port scanner | `scripts/network_scan.py` — fast path for host discovery | Seconds instead of minutes on large ranges | **Degrades** — falls back to `nmap -sn` automatically |
| `go` | Go toolchain | `deploy.py` — `go install` for the Go tools | Compiling and installing nuclei, httpx and subfinder | **Degrades** — the Go tools cannot be installed |
| `pip` + `python3-venv` | Python packaging and virtualenv | `deploy.py`, `deployment-manifest.md` | Installing the Python dependencies into a venv — PEP 668 distros refuse system-level installs | **Hard stop** — the Python dependencies cannot be installed |
| `nodejs` + `npm` | Node runtime | `deploy.py` — `npx skills add …` | Installing the Anthropic Cybersecurity Skills layer the agent works from | **Degrades** — the agent skill layer cannot be installed |

## Optional — rendering only

Installed by `deploy.py`, but no code path invokes it and no pipeline output depends on it.

| Tool | What it is | Used by | Why | If missing |
|---|---|---|---|---|
| `graphviz` (`dot`) | DOT renderer | Not invoked — `scripts/topology.py --dot` *emits* DOT text | Rendering the topology diagram to an image, by hand | **No effect** — no diagram image; the DOT text output is unchanged |

## Local LLM

Required for `--mode local`. Used opportunistically in `--mode hybrid`, which falls back to
the cloud LLM if it is absent.

| Tool | What it is | Used by | Why | If missing |
|---|---|---|---|---|
| `llama-server` (llama.cpp b9870+) | Local inference server | `portshim server start|stop|status` (PID file `~/.hermes/llama-server.pid`), `scripts/benchmark-models.py` | Local model inference for recon/CVE analysis and exploit reasoning | Local mode unavailable; hybrid falls back to the cloud LLM |

Model files are a separate dependency — see `references/llm-architecture.md`. Required GGUFs
live under `~/local-models/` (override with `PD_MODELS_DIR`).

## Wireless module — `portshim wireless …`

Requires an **external USB adapter**. The internal interface is never used.

| Tool | What it is | Used by | Why | If missing |
|---|---|---|---|---|
| `iw` | nl80211 interface control | `scripts/wireless_hardware.py`, `scripts/wireless_scan.py`, `scripts/wireless_assess.py` | Interface enumeration, capability probing, managed-mode scans, association check | Wireless module unusable |
| `nmcli` | NetworkManager client | `scripts/wireless_hardware.py`, `scripts/wireless_scan.py` | Detects NetworkManager interference before capture | Interference detection skipped — captures may fail mysteriously |
| `airmon-ng` | Monitor-mode management | `scripts/wireless_scan.py` | Enables monitor mode | No capture possible |
| `airodump-ng` | Passive wireless capture | `scripts/wireless_scan.py`, `scripts/wireless_capture.py`, `scripts/wireless_deauth.py`, `scripts/wireless_hardware.py` | AP discovery and handshake capture | Scan and capture fail |
| `aireplay-ng` | Frame injection | `scripts/wireless_deauth.py`, `scripts/wireless_hardware.py` | Deauth to force a handshake | Deauth unavailable |
| `aircrack-ng` | Wireless protocol cracking | `scripts/wireless_crack.py`, `scripts/wireless_capture.py`, `scripts/wireless_deauth.py` | WEP/PSK cracking and capture verification | Cracking unavailable |
| `hcxdumptool` | PMKID capture | `scripts/wireless_capture.py`, `scripts/wireless_pmkid.py` | Capture path that survives PMF | PMKID route unavailable |
| `hcxpcapngtool` | pcapng → hashcat/john format | `scripts/wireless_capture.py`, `scripts/wireless_crack.py`, `scripts/wireless_pmkid.py` | Converts captures into crackable hashes | No cracking input |
| `macchanger` | MAC spoofing | `scripts/wireless_hardware.py` | Operator identity hygiene | Adapters retain their real MAC |
| `hashcat` | GPU-accelerated cracking | `scripts/wireless_crack.py`, `scripts/wireless_pmkid.py` | Candidate and wordlist attacks | Cracking unavailable |
| `john` | CPU cracking | `scripts/wireless_crack.py` | Fallback when there is no usable GPU | No GPU-less cracking fallback |
| `hashid` | Hash type identification | `scripts/wireless_crack.py` (invoked as a binary via `shutil.which`) | Identifies the hash format in a capture | Hash type auto-detection skipped |

## Exploit phase

| Tool | What it is | Used by | Why | If missing |
|---|---|---|---|---|
| `searchsploit` (exploitdb) | Local Exploit-DB search | `scripts/generate-findings.py` — `lookup_exploit()` | Maps verified CVEs to public exploits | Findings carry no exploit references |
| `hydra` | Credential brute force | Not invoked — **Agent**: Phase 3 credential testing per the skill | — | Phase 3 credential checks unavailable |
| `sshpass` | Non-interactive SSH auth | Not invoked — **Agent**: Phase 3 SSH work per the skill | — | Interactive prompts block automated SSH |

## Installed and configured, but run by the agent (not by code)

These are installed by `deploy.py` and configured for the pipeline, but no script invokes
them. The Hermes agent runs them per the `site-assessment-pipeline` skill, and
`scripts/engagement-profiles.py` supplies the per-profile flags.

| Tool | What it is | Configuration | If missing |
|---|---|---|---|
| `nuclei` | Template-based vulnerability scanner | Flags per stealth profile (`-severity …`, `-rl …`) in `engagement-profiles.py`; commands in the skill | Phase 2 relies on nmap-vulners CVE data alone |
| `httpx` | HTTP probing → JSON | Flags per stealth profile in `engagement-profiles.py`; `topology.py --httpx <file>` consumes its JSON output | Topology loses HTTP titles and tech-stack data |
| `subfinder` | Subdomain enumeration | Credited in the README's open-source list and installed by `deploy.py`, but **no flags configured and no invocation anywhere in the repo** | No effect on internal LAN engagements — see gap 5 below |
| `metasploit` | Exploit framework | Opt-in: `python deploy.py --with-msf`. Not referenced by code | Phase 3 exploit verification is limited to manual techniques |
| `kismet` | Wireless IDS / passive capture | Skill reference only. The sole code mention is a `.kismet.csv` cleanup pattern in `scripts/wireless_scan.py` | No effect |

## Not a dependency

| Tool | Status |
|---|---|
| `tshark` / `tcpdump` | Not used anywhere in the codebase. Packet capture for protocol-level exploit verification is an open feature request — issue #42 |

## Python packages

`deploy.py` installs these into the project venv. The "imported by" column is the verified
result of scanning every `import` in the tree.

| Package | Import name | Imported by | Notes |
|---|---|---|---|
| `python-docx` | `docx` | `scripts/_build_docx.py`, `scripts/render-docs.py`, `scripts/report-gen.py` | Technical report |
| `python-pptx` | `pptx` | `scripts/report-gen.py` | Executive deck |
| `openpyxl` | `openpyxl` | `scripts/excel-checklist.py`, `scripts/retest-diff.py` | Remediation checklist |
| `pyyaml` | `yaml` | `scripts/sync_knowledge.py`, `scripts/check-skill-freshness.py` | Knowledge-source manifests |
| `hashid` | — | Not imported — provides the `hashid` **binary** used by `wireless_crack.py` | Installed as a pip package, consumed as a subprocess |
| `Pillow` | `PIL` | `scripts/build-shorts.py`, `scripts/build-video.py`, `scripts/build_slides.py` | **Not installed by `deploy.py`** — see gap 1 |
| `numpy` | `numpy` | `scripts/build-shorts.py`, `scripts/build-video.py`, `scripts/generate-bg-music.py` | **Not installed by `deploy.py`** — see gap 1 |
| `requests` | — | Not imported anywhere | See gap 4 |
| `fpdf2` | `fpdf` | Not imported anywhere | See gap 4 |
| `paramiko` | — | Not imported anywhere | See gap 4 |

## Toolchain gaps found in the 2026-09-21 audit

Recorded here rather than silently worked around. None of these block the core wired pipeline.

1. **Pillow and numpy are undeclared.** The video pipeline scripts import them, but they are
   in neither `deploy.py` nor `pyproject.toml` — a fresh deploy cannot run `build-shorts.py`,
   `build-video.py`, `build_slides.py` or `generate-bg-music.py`.
2. **ffmpeg is undeclared.** `scripts/build-shorts.py` invokes `ffmpeg` directly; it is not
   installed by `deploy.py`.
3. **curl and iproute2 are invoked but not installed.** Both are near-universal on Linux
   desktops, so this is a documentation gap more than a functional one.
4. **requests, fpdf2 and paramiko are installed but never imported** by any file in the tree.
5. **subfinder is documented but unused.** It is credited in the README's open-source list and
   installed by `deploy.py`; no script invokes it and no profile configures it.
6. **graphviz is installed; only the DOT text is produced.** `topology.py --dot` writes DOT
   source — installing graphviz only matters if the operator renders it.
7. **The `portshim` preflight checks four tools only** (`nmap`, `nuclei`, `httpx`,
   `llama-server`). The other entries in this document fail at first use, mid-phase.

## Verification

```bash
# Tool inventory (matches deploy.py)
which nmap ip curl git masscan
which llama-server iw nmcli airmon-ng airodump-ng aireplay-ng aircrack-ng \
      hcxdumptool hcxpcapngtool macchanger hashcat john hashid searchsploit hydra sshpass \
      nuclei httpx subfinder msfconsole kismet

# Python packages actually importable
.venv/bin/python -c "import openpyxl, docx, pptx, yaml, PIL, numpy; print('OK')"
# note: the module is `fpdf`, not `fpdf2`

# Knowledge sources pinned and fresh
.venv/bin/python scripts/check-skill-freshness.py
```

## Package → binary map

`deploy.py` installs packages; several provide the binaries the code invokes.

| Package | Provides |
|---|---|
| `aircrack-ng` | `aircrack-ng`, `airmon-ng`, `airodump-ng`, `aireplay-ng` |
| `hcxtools` | `hcxpcapngtool` |
| `hcxdumptool` | `hcxdumptool` |
| `exploitdb` | `searchsploit` |
| `graphviz` | `dot` |
| `iproute2` | `ip` — not installed by `deploy.py` (see gap 3) |
| `curl` | `curl` — not installed by `deploy.py` (see gap 3) |

## Related

- `references/deployment-manifest.md` — per-distro install commands
- `references/llm-architecture.md` — model and server architecture
- `references/agent-integration.md` — driving the harness from an agent, end to end
- Website: `pages/dependencies.html` mirrors this document for the public
  site. **The two must change together** — the page is hand-maintained, not generated.

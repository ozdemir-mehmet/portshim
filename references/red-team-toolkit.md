# Red Team Toolkit Reference

Condensed from `infosecn1nja/red-teaming-toolkit` — organised by attack lifecycle phase.
Full source at: https://github.com/infosecn1nja/red-teaming-toolkit

> **Knowledge Source:** Tracked in `skills/site-assessment-pipeline/sources.yaml`
> **Sync:** `python scripts/sync_knowledge.py --skill site-assessment-pipeline`

---

## Reconnaissance

| Tool | Purpose |
|---|---|
| RustScan | Fast port scanner (3s for all ports) |
| Amass | Attack surface mapping, asset discovery |
| gitleaks | Detect hardcoded secrets in git repos |
| S3Scanner | Open S3 bucket enumeration |
| cloud_enum | Multi-cloud (AWS, Azure, GCP) enumeration |
| SpiderFoot | OSINT automation |
| BBOT | Recursive internet scanner |
| Gato | GitHub pipeline vulnerability exploitation |

## Initial Access — Payload Development

| Tool | Purpose |
|---|---|
| ScareCrow | EDR bypass payload framework |
| Donut | In-memory .NET/EXE/DLL execution |
| PEzor | PE packer for AV evasion |
| Freeze | Suspended process + direct syscalls |
| Shhhloader | Shellcode loader with AV bypass |
| inceptor | Template-driven AV/EDR evasion |
| macro_pack | MS Office document obfuscation |
| EvilClippy | Malicious Office doc creation |

## Command & Control

| Tool | Type |
|---|---|
| Cobalt Strike | Commercial C2 (industry standard) |
| Sliver | Cross-platform implant (mTLS/HTTP/DNS) |
| Havoc | Modern C2 framework |
| Mythic | Docker-based cross-platform C2 |
| Covenant | .NET C2 platform |
| Empire | PowerShell/Python post-exploitation |
| Merlin | Go-based HTTP/2 C2 |
| NimPlant | Lightweight Nim C2 implant |
| PoshC2 | Proxy-aware C2 framework |

## Credential Dumping

| Tool | Purpose |
|---|---|
| Mimikatz | Credential extraction (gold standard) |
| Dumpert | LSASS dump via direct syscalls |
| SharpDPAPI | DPAPI credential decryption |
| nanodump | LSASS minidump via BOF |
| LaZagne | Multi-app password recovery |
| pypykatz | Mimikatz in pure Python |
| PPLBlade | Protected process dumper |

## Privilege Escalation

| Tool | Purpose |
|---|---|
| PEASS-ng | Privilege escalation script suite |
| SweetPotato | Service → SYSTEM via SeImpersonate |
| Watson | Missing-KB based privesc suggestions |
| KrbRelayUp | LDAP signing bypass privesc |
| GodPotato | ImpersonatePrivilege → SYSTEM |

## Defense Evasion

| Tool | Purpose |
|---|---|
| EDRSandBlast | EDR bypass via vulnerable driver |
| Mangle | Executable manipulation for AV evasion |
| AceLdr | Cobalt Strike UDRL for memory evasion |
| SigFlip | Patch signed PE without breaking signature |
| PoolParty | Process injection via Windows thread pools |
| EDRSilencer | Block EDR via Windows Filtering Platform |

## Lateral Movement

| Tool | Purpose |
|---|---|
| CrackMapExec | Swiss army knife for network pentesting |
| impacket | Python network protocol library |
| SharpRDP | RDP console for command execution |
| Coercer | Force Windows auth via 9 methods |
| kerbrute | Kerberos user enumeration |
| LiquidSnake | Fileless WMI lateral movement |
| SCShell | Fileless lateral via ChangeServiceConfig |

## Tunneling

| Tool | Purpose |
|---|---|
| Chisel | Fast TCP/UDP tunnel over HTTP |
| frp | Fast reverse proxy for NAT traversal |
| ligolo-ng | TUN-interface tunneling |

## Cloud — AWS

| Tool | Purpose |
|---|---|
| pacu | AWS exploitation framework |
| CloudMapper | AWS environment analysis |
| enumerate-iam | IAM permission enumeration |

## Cloud — Azure

| Tool | Purpose |
|---|---|
| ROADtools | Azure AD exploration |
| Stormspotter | Azure/AD object graphing |
| MicroBurst | Azure security assessment |
| GraphRunner | Microsoft Graph post-exploitation |
| TeamFiltration | O365 enumeration/backdooring |

## Adversary Emulation

| Tool | Purpose |
|---|---|
| Caldera (MITRE) | Automated adversary emulation |
| Atomic Red Team | Detection tests mapped to ATT&CK |
| Stratus Red Team | Cloud attack emulation |
| TTPForge (Meta) | TTP development framework |

## AI Red Teaming

| Tool | Purpose |
|---|---|
| Garak (NVIDIA) | LLM vulnerability scanner |
| PyRIT (Microsoft) | Generative AI risk identification |
| promptfoo | LLM red-teaming CLI |
| FuzzyAI (CyberArk) | Automated LLM fuzzing |

## Living Off the Land

| Resource | Focus |
|---|---|
| GTFOBins | Unix binary abuse |
| LOLBAS | Windows binary abuse |
| LOTS Project | Trusted site abuse |
| LOOBins | macOS binary abuse |
| Hijack Libs | DLL hijacking candidates |

## Reporting & Tracking

| Tool | Purpose |
|---|---|
| Ghostwriter | Red team operations management |
| VECTR | Red/blue test tracking |
| PurpleOps | Purple team management |

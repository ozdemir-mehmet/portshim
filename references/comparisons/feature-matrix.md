# Feature Matrix — PortShim vs Competitors

> Updated: July 2026 (post-benchmark, CLI wrapper, SQLite scan history)

---

## Full Feature Matrix

| Feature | PentestGPT<br>14K ★ | RedAmon<br>2.1K ★ | AIRecon<br>778 ★ | AutoPentestX<br>1.2K ★ | AutoPWN<br>1K ★ | **PortShim** |
|---|---|---|---|---|---|---|
| **One-command start** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ `portshim scan` |
| **Network-wide (CIDR)** | ✅ | ❓ | ❓ | ❌ | ❌ | ✅ |
| **Device classification** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 40+ roles |
| **Stealth profiles** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 3 profiles |
| **Operator review gates** | ⚠️ Partial | ❌ | ⚠️ TUI | ❌ | ❌ | ✅ 6 gates |
| **LLM-powered exploitation** | ✅ Cloud | ✅ Cloud | ✅ Local | ❌ | ❌ | ✅ Multi-engine |
| **Benchmark-driven model selection** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 4 models tested |
| **Multi-model (local+cloud)** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 3 modes |
| **Wireless testing** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Retest phase** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Multi-format reports** | ❌ | ❌ | ❌ | PDF only | ❌ | ✅ docx+pptx+xlsx |
| **Remediation tracking** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ xlsx checklist |
| **Cross-engagement analytics** | ❌ | ❌ | ❌ | SQLite | ❌ | ✅ SQLite + stats |
| **Knowledge-source tracking** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Commit-pinned |
| **Operator documentation** | ❌ | ❌ | ❌ | Minimal | ❌ | ✅ 4-doc suite |
| **Distro-agnostic deploy** | ❌ | ❌ | ✅ Docker | ❌ | ❌ | ✅ apt/dnf/pacman/... |
| **Offline capable** | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ Local mode |
| **Docker sandbox** | ❌ | ❌ | ✅ | ❌ | ❌ | ⚠️ Roadmap (low) |

---

## Scorecard

| | PentestGPT | RedAmon | AIRecon | AutoPentestX | AutoPWN | **PortShim** |
|---|---|---|---|---|---|---|
| ✅ Features | 4 | 3 | 6 | 4 | 2 | **17** |
| ⚠️ Partial | 1 | 0 | 1 | 0 | 0 | 0 |
| ❌ Missing | 13 | 15 | 11 | 14 | 16 | 1 |
| **Coverage** | 22% | 17% | 33% | 22% | 11% | **94%** |

---

## By Category

### Setup & Deployment

| | PentestGPT | RedAmon | AIRecon | AutoPentestX | AutoPWN | **PortShim** |
|---|---|---|---|---|---|---|
| One-command start | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Distro-agnostic | ❌ | ❌ | ✅ Docker | ❌ | ❌ | ✅ |
| Offline capable | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Operator docs | ❌ | ❌ | ❌ | Minimal | ❌ | ✅ 4 docs |

### Scanning & Recon

| | PentestGPT | RedAmon | AIRecon | AutoPentestX | AutoPWN | **PortShim** |
|---|---|---|---|---|---|---|
| Network-wide | ✅ | ❓ | ❓ | ❌ | ❌ | ✅ |
| Device classification | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Stealth profiles | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Wireless testing | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

### Exploitation & Control

| | PentestGPT | RedAmon | AIRecon | AutoPentestX | AutoPWN | **PortShim** |
|---|---|---|---|---|---|---|
| LLM-powered | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Multi-model | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Benchmark-driven | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Operator gates | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ✅ |
| Docker sandbox | ❌ | ❌ | ✅ | ❌ | ❌ | ⚠️ Roadmap (low) |

### Reporting & Tracking

| | PentestGPT | RedAmon | AIRecon | AutoPentestX | AutoPWN | **PortShim** |
|---|---|---|---|---|---|---|
| Multi-format | ❌ | ❌ | ❌ | PDF | ❌ | ✅ 3 formats |
| Remediation tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Retest phase | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Cross-engagement analytics | ❌ | ❌ | ❌ | SQLite | ❌ | ✅ |
| Knowledge tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

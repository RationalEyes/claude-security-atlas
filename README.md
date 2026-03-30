<p align="center">
  <img src="https://img.shields.io/badge/%F0%9F%9B%A1%EF%B8%8F_Claude_Security-Atlas-8B5CF6?style=for-the-badge&labelColor=1e1e2e" alt="Claude Security Atlas" />
</p>

<h1 align="center">Claude Security Atlas</h1>

<p align="center">
  <strong>A modular cybersecurity guide mapping prompt injection attack surfaces across all Claude environments</strong><br/>
  <em>Threat taxonomy &bull; Defense skills &bull; Attack examples &bull; Test pages &bull; Technical manual</em>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-22c55e?style=flat-square" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/Python-3.8%2B-3b82f6?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/Vectors-24_cataloged-ef4444?style=flat-square" alt="24 Vectors" />
  <img src="https://img.shields.io/badge/Defense_Skills-6_installable-22c55e?style=flat-square" alt="6 Defense Skills" />
  <img src="https://img.shields.io/badge/Modules-2_complete_%7C_6_planned-a855f7?style=flat-square" alt="8 Modules" />
</p>

---

<br/>

> [!CAUTION]
> **Claude's prompt injection attack surface extends far beyond chat.** Skills execute with system-prompt authority. Web content flows into agent reasoning without trust boundaries. MCP servers bridge untrusted networks. Every input channel is a potential injection vector — and most have no defense by default.

<br/>

<table>
<tr>
<td width="50%">

### The Threat Landscape

- **36.82%** of 3,984 community skills contained security flaws<br/><sup>Snyk ToxicSkills, February 2026</sup>
- **80%** attack success rate on frontier models<br/><sup>Skill-Inject benchmark, arXiv:2602.20156</sup>
- **335** coordinated malicious skills in a single campaign<br/><sup>ClawHavoc / Snyk, February 2026</sup>
- **73%** of production AI deployments affected by indirect prompt injection<br/><sup>Gartner AI Security Report, 2025</sup>
- **Zero** signing, vetting, or provenance verification for skills

</td>
<td width="50%">

### What This Guide Provides

- **24-vector threat taxonomy** across 2 attack surfaces (SKI + WCI)
- **6 installable defense skills** — scanners, verifiers, guardrails, filters
- **6 attack examples** — educational skill-based demonstrations
- **12 HTML test pages** — red/blue team web injection testing
- **Platform security analysis** — Claude Web vs Cowork vs Code
- **Unified technical manual** covering architecture to regulation

</td>
</tr>
</table>

<br/>

---

## Modules

| Module | Status | Attack Surface | Vectors | Defense Skills |
|:---|:---:|:---|:---:|:---:|
| [`claude-skills/`](claude-skills/) | ✅ Complete | Skill injection (SKILL.md, scripts, triggers) | 12 (SKI-001..012) | 3 |
| [`web-content/`](web-content/) | ✅ Complete | Web content injection (HTML, search, fetch) | 12 (WCI-001..012) | 3 |
| `mcp-servers/` | 📋 Planned | MCP server security | — | — |
| `project-files/` | 📋 Planned | Project file & config injection | — | — |
| `multi-agent/` | 📋 Planned | Multi-agent orchestration security | — | — |
| `computer-use/` | 📋 Planned | Browser automation & computer use | — | — |
| `memory-persistence/` | 📋 Planned | Memory & context persistence | — | — |
| `exfiltration-channels/` | 📋 Planned | Data exfiltration patterns | — | — |

### Planned Modules

**MCP Server Security** — Malicious or compromised MCP servers, tool poisoning via description injection, tool shadowing, protocol-level exploits. Covers CVE-2025-6514 (CVSS 9.6), the Smithery registry breach, and SANDWORM_MODE campaigns. *Priority: HIGH*

**Project File & Configuration Injection** — Weaponized CLAUDE.md, .claude/settings.json, hooks, .cursorrules, and .vscode/settings.json. Covers CVE-2025-59536 (hooks RCE, CVSS 8.7) and CVE-2026-21852 (API token exfiltration). Every git clone is a potential attack vector. *Priority: HIGH*

**Multi-Agent & Orchestration Security** — Agent-to-agent prompt infection, tainted instruction dispatch, orchestrator hijacking, shared memory poisoning. Based on Lee & Tiwari's Prompt Infection research (80%+ LLM-to-LLM infection rate). *Priority: MEDIUM*

**Computer Use & Browser Automation Security** — Pixel-level injection in Playwright/browser automation, adversarial UI elements, screenshot-based exfiltration, clickjacking the agent. Based on CaMeL for CUAs (arXiv:2601.09923). *Priority: MEDIUM*

**Memory & Persistence Security** — Memory poisoning (injecting false memories across sessions), cache poisoning, CLAUDE.md manipulation. Threats that survive conversation boundaries. *Priority: MEDIUM*

**Data Exfiltration Channels** — Steganographic exfiltration (base64, invisible unicode), side-channel via timing/error messages, covert channels through legitimate tool use. Cross-cutting concern spanning all modules. *Priority: LOW*

---

## Quick Start: Install Defense Skills

> [!TIP]
> These are **real, working Claude Skills**. Copy them into your skills directory and they activate automatically in Claude Code.

```bash
# Clone the repo
git clone https://github.com/RationalEyes/claude-security-atlas.git
cd claude-security-atlas

# Install Module 1: Skills defense
cp -r claude-skills/skills/security-monitor     ~/.claude/skills/security-monitor
cp -r claude-skills/skills/hash-verifier         ~/.claude/skills/hash-verifier
cp -r claude-skills/skills/output-sanitizer      ~/.claude/skills/output-sanitizer

# Install Module 2: Web content defense
cp -r web-content/skills/web-content-scanner     ~/.claude/skills/web-content-scanner
cp -r web-content/skills/search-guardrail        ~/.claude/skills/search-guardrail
cp -r web-content/skills/real-time-content-filter ~/.claude/skills/real-time-content-filter
```

Then just talk to Claude:

| Say this in Claude Code | What happens |
|---|---|
| *"Scan my installed skills for security issues"* | Runs static analysis on all skill files |
| *"Verify skill integrity"* | Checks SHA-256 hashes against known-good manifest |
| *"Scan this URL for injection attacks"* | Audits web content for all 12 WCI patterns |
| *"Search with guardrails for [topic]"* | Filters search results through injection scanner |
| *"Enable content filtering"* | Activates real-time behavioral guardrails |

---

## Defense Skills

<table>
<tr>
<td width="50%" valign="top">

### Module 1: Skills Defense

**🔍 Security Monitor** — Static analysis scanner for SKILL.md and scripts. Detects external URLs, credential access, persistence mechanisms, authority impersonation, hidden content.

**🔐 Hash Verifier** — Cryptographic integrity checker. Generates SHA-256 manifests and detects modified, added, or deleted files. Catches rug-pull and supply-chain attacks.

**🧹 Output Sanitizer** — Second-order injection prevention. Strips injection patterns, credential exposure, and encoded payloads from script output before it enters Claude's context.

</td>
<td width="50%" valign="top">

### Module 2: Web Content Defense

**🌐 Web Content Scanner** — Pre-ingestion HTML audit. Scans fetched pages for all 12 WCI vectors (comments, CSS-hidden text, encoded payloads, authority spoofing, unicode obfuscation, JSON-LD poisoning). Outputs risk score 0-100.

**🔎 Search Guardrail** — Search result filter. Fetches and scans each result before Claude processes it. Configurable threshold: block CRITICAL, flag HIGH, pass MEDIUM/LOW.

**🛡️ Real-Time Content Filter** — Behavioral guardrail. Injects trust hierarchy and self-audit instructions. No script — operates as reasoning-level defense.

</td>
</tr>
</table>

---

## Threat Taxonomy

> [!IMPORTANT]
> This guide catalogs **24 attack vectors** across **2 attack surfaces**, mapped to the [Promptware Kill Chain](https://arxiv.org/abs/2601.09625), [MITRE ATLAS](https://atlas.mitre.org/), and [OWASP Agentic Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

### Module 1: Skills Injection (SKI)

| ID | Vector | Risk | Complexity |
|:---|:---|:---:|:---:|
| **SKI-001** | SKILL.md Content Poisoning | `CRITICAL` | Low |
| **SKI-002** | Skill Trigger Hijacking | `HIGH` | Low |
| **SKI-003** | User-Uploaded Skill Persistence | `CRITICAL` | Low |
| **SKI-004** | Script-Based Host Compromise | `CRITICAL` | Medium |
| **SKI-005** | Second-Order Context Poisoning | `CRITICAL` | High |
| **SKI-006** | Skill Chaining / Cross-Contamination | `HIGH` | High |
| **SKI-007** | Metadata / Frontmatter Manipulation | `HIGH` | Low |
| **SKI-008** | Supply Chain Attack on Repositories | `CRITICAL` | Medium |
| **SKI-009** | Multi-Agent Skill Propagation | `CRITICAL` | High |
| **SKI-010** | Cache Poisoning via Early Activation | `HIGH` | High |
| **SKI-011** | Skill-as-Command-and-Control | `CRITICAL` | Medium |
| **SKI-012** | Skill Authority Paradox (Architectural) | `CRITICAL` | Low |

### Module 2: Web Content Injection (WCI)

| ID | Vector | Risk | Complexity |
|:---|:---|:---:|:---:|
| **WCI-001** | Hidden HTML Comment Injection | `HIGH` | Low |
| **WCI-002** | CSS-Hidden Text Injection | `HIGH` | Low |
| **WCI-003** | Encoded Payload in Meta/Data Attributes | `MEDIUM` | Medium |
| **WCI-004** | Authority Spoofing in Page Content | `CRITICAL` | Low |
| **WCI-005** | Markdown Injection via Web Content | `HIGH` | Medium |
| **WCI-006** | Multi-Page Chain Injection | `HIGH` | High |
| **WCI-007** | Unicode/Homoglyph Obfuscation | `HIGH` | Medium |
| **WCI-008** | Poisoned Structured Data (JSON-LD) | `HIGH` | Medium |
| **WCI-009** | Search Result Poisoning / SEO Injection | `CRITICAL` | Medium |
| **WCI-010** | Dynamic JavaScript-Generated Injection | `MEDIUM` | Medium |
| **WCI-011** | Image/Media Alt-Text and EXIF Injection | `MEDIUM` | Low |
| **WCI-012** | Fetch Response Header Injection | `LOW` | Medium |

**10 CRITICAL** &bull; **10 HIGH** &bull; **3 MEDIUM** &bull; **1 LOW**

See [`docs/threat-taxonomy.md`](docs/threat-taxonomy.md) for full details with MITRE ATLAS and OWASP mappings.

---

## Platform Security Dimensions

The same vector has radically different impact across Claude's three platforms:

| Dimension | Claude Web | Claude Cowork | Claude Code |
|:---|:---:|:---:|:---:|
| Filesystem access | None | Sandbox only | **Full** |
| Shell execution | None | Limited | **Full** |
| Web fetch/search | None | Tools available | **WebFetch + WebSearch + Playwright** |
| Skills support | None | None | **Full** |
| Active SKI vectors | 0 | 0 | **12** |
| Active WCI vectors | 4 (paste only) | 8 (sandboxed) | **12 (all)** |
| Overall risk | Low | Medium | **Critical** |

See [`docs/platform-dimensions.md`](docs/platform-dimensions.md) for detailed analysis.

---

## Test Pages (Red/Blue Team)

> [!WARNING]
> These are for **educational and defensive research only**. All payloads use non-functional placeholder endpoints.

12 HTML test pages disguised as professional websites, each hiding a specific WCI injection:

```bash
cd web-content/test-pages
python -m http.server 8080
# Then test: "Fetch http://localhost:8080/04-authority-spoofing.html and summarize it"
```

Use the **Web Content Scanner** to test detection:
```bash
python3 web-content/skills/web-content-scanner/scripts/scan_web_content.py \
    web-content/test-pages/04-authority-spoofing.html
```

See [`web-content/test-pages/README.md`](web-content/test-pages/README.md) for the full testing guide.

---

## Documentation

| Document | Description | PDF |
|:---|:---|:---:|
| 📖 [`docs/technical-manual.md`](docs/technical-manual.md) | Complete technical manual — architecture, all 24 vectors, defense layers, regulatory context (~20,000+ words) | [PDF](docs/technical-manual.pdf) |
| 🗂️ [`docs/threat-taxonomy.md`](docs/threat-taxonomy.md) | Unified 24-vector taxonomy with MITRE ATLAS and OWASP cross-references | [PDF](docs/threat-taxonomy.pdf) |
| 🌐 [`docs/platform-dimensions.md`](docs/platform-dimensions.md) | Platform security comparison — Claude Web vs Cowork vs Code | — |
| 📊 [`docs/attack-path-diagrams.md`](docs/attack-path-diagrams.md) | 13 Mermaid diagrams: attack paths, defense layers, risk matrices | [PDF](docs/attack-path-diagrams.pdf) |
| 📋 [`docs/executive-summary.md`](docs/executive-summary.md) | Non-technical summary for leadership and governance audiences | [PDF](docs/executive-summary.pdf) |
| 💼 LinkedIn Article | Thought leadership on Claude Skills security risks | [PDF](docs/linkedin-article.pdf) |

---

## Key References

| Source | Citation |
|:---|:---|
| Skill-Inject benchmark | Schmotz et al., arXiv:2602.20156, February 2026 |
| Promptware Kill Chain | Schneier et al., arXiv:2601.09625, February 2026 |
| SoK: Prompt Injection in Coding Assistants | arXiv:2601.17548, January 2026 |
| Snyk ToxicSkills | snyk.io/blog/toxicskills, February 2026 |
| Indirect Prompt Injection (foundational) | Greshake et al., arXiv:2302.12173, 2023 |
| CaMeL defense framework | Debenedetti et al., arXiv:2503.18813, March 2025 |
| CaMeL for Computer Use Agents | arXiv:2601.09923, January 2026 |
| Prompt Infection (LLM-to-LLM) | Lee & Tiwari, arXiv:2410.07283, COLM 2025 |
| Agents Rule of Two | Meta AI, arXiv:2512.00966, October 2025 |
| MITRE ATLAS | October 2025 update — 14 new agentic AI techniques |
| OWASP Agentic Top 10 | December 2025 |
| OWASP LLM Top 10 | 2025 edition |

---

## Requirements

- **Python 3.8+**
- **PyYAML** *(optional)* — for frontmatter parsing in security-monitor

```bash
pip install pyyaml  # optional
```

---

## Contributing

Contributions welcome — especially:

- New detection patterns for scanners
- Additional defense skill ideas
- Real-world case studies (anonymized)
- Improvements to the threat taxonomy
- New module development (see planned modules above)

Please ensure attack examples remain non-functional and clearly marked as educational.

---

## License

[MIT](LICENSE)

---

<br/>

> [!NOTE]
> This project is for **educational and defensive security research purposes only**. Attack examples and test pages use non-functional placeholder endpoints and must not be deployed in live environments. The authors are not responsible for misuse of the techniques described.

<br/>

<p align="center">
  <a href="https://github.com/RationalEyes"><img src="https://img.shields.io/badge/RationalEyes.ai-Claude_Security_Atlas-8B5CF6?style=for-the-badge&labelColor=1e1e2e" alt="RationalEyes.ai" /></a>
  &nbsp;
  <img src="https://img.shields.io/badge/Built_with-Claude_Code_Agent_Teams-6366f1?style=for-the-badge&labelColor=1e1e2e" alt="Built with Claude Code Agent Teams" />
</p>

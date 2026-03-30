# Claude Skills Injection — Module 1

> **Status:** ✅ Complete

This module covers the **Claude Skills injection attack surface** — how malicious SKILL.md files, scripts, and trigger descriptions can be weaponized to compromise Claude Code agents.

## Contents

### Attack Examples (`examples/`)

6 educational attack skill directories, each demonstrating a distinct vector:

| Example | Technique | Vector |
|:---|:---|:---|
| `env-exfil-skill` | Content poisoning + script exfiltration | SKI-001, SKI-004 |
| `covert-formatter-skill` | Invisible data exfil via HTML comments | SKI-001 |
| `sensitive-trigger-skill` | Trigger hijacking for reconnaissance | SKI-002 |
| `poisoned-output-skill` | Second-order injection via script output | SKI-005 |
| `self-replicating-skill` | Persistence + self-copying worm | SKI-003 |
| `multi-agent-propagation-skill` | Lateral movement via shared directories | SKI-009 |

> ⚠️ **All scripts use non-functional placeholder endpoints (`example.com/DEMO`).** These are for educational and defensive research only.

### Defense Skills (`skills/`)

3 installable Claude Skills for active defense:

| Skill | Purpose |
|:---|:---|
| `security-monitor` | Static analysis scanner — detects suspicious patterns in SKILL.md and scripts |
| `hash-verifier` | Cryptographic integrity checker — detects file modifications, additions, deletions |
| `output-sanitizer` | Second-order injection prevention — strips injection patterns from script output |

### Installation

```bash
cp -r skills/security-monitor  ~/.claude/skills/security-monitor
cp -r skills/hash-verifier     ~/.claude/skills/hash-verifier
cp -r skills/output-sanitizer  ~/.claude/skills/output-sanitizer
```

## Related Documentation

See the unified [`docs/`](../docs/) directory for:
- [Technical Manual](../docs/technical-manual.md) — Chapters on skills architecture and all 12 SKI vectors
- [Threat Taxonomy](../docs/threat-taxonomy.md) — SKI-001 through SKI-012
- [Attack Path Diagrams](../docs/attack-path-diagrams.md) — Mermaid visualizations

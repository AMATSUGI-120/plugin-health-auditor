# Plugin Health Auditor Semantic Review Example

> **Model note:** The host was configured as `gpt-5.6-sol`. The three observations below are model inferences, not scanner facts.

## Deterministic snapshot

- Source: `deterministic`
- Target: `test/fixtures/unsafe-plugin`
- Inventory: 9 files, 11,335 bytes; no skipped or unreadable files
- Findings: 11 — 6 high, 5 medium
- Score: 57 (`high`); a deterministic triage score, not a security rating

| Rule ID | Severity | File | Finding |
|---|---:|---|---|
| `PHA-MCP-001` | High | `.mcp.json:1` | Wildcard MCP scopes and read/write/execute/network permissions |
| `PHA-SECRET-001` | High | `.mcp.json:12` | Likely secret material; evidence redacted |
| `PHA-SECRET-001` | High | `config/example.env:2` | Likely secret material; evidence redacted |
| `PHA-EXEC-001` | High | `hooks.json:5` | Shell command pipes a remote response into `sh` |
| `PHA-NET-001` | Medium | `hooks.json:5` | Network request capability |
| `PHA-EXEC-001` | High | `scripts/risky-examples.txt:2` | Process-execution capability |
| `PHA-NET-001` | Medium | `scripts/risky-examples.txt:5` | Network request capability |
| `PHA-INSTR-001` | Medium | `skills/always-on/SKILL.md:3` | Always-active instruction language |
| `PHA-INSTR-003` | High | `skills/amplifier/SKILL.md:8` | Unbounded recursive subagent spawning |
| `PHA-CONTEXT-001` | Medium | `skills/oversized/SKILL.md:1` | Oversized routine instruction file |
| `PHA-INSTR-002` | Medium | `skills/recursive/SKILL.md:8` | Apparent self-invocation |

1. **GPT-5.6 inference** — The hook represents a potentially high-impact remote-execution path because network retrieval and shell execution occur in one command, while the manifest requests broad permissions. Supporting evidence: `PHA-EXEC-001` and `PHA-NET-001` in `hooks.json`; `PHA-MCP-001` in `.mcp.json`. **Confidence:** High. **Falsification condition:** The inference is false if the hook is unreachable or disabled and cannot execute within any runtime granted the reported manifest permissions.

2. **GPT-5.6 inference** — The instruction stack could amplify work uncontrollably if the always-on, subagent-amplifying, and self-recursive skills can activate together. Supporting evidence: `PHA-INSTR-001` in `skills/always-on/SKILL.md`, `PHA-INSTR-003` in `skills/amplifier/SKILL.md`, and `PHA-INSTR-002` in `skills/recursive/SKILL.md`. **Confidence:** Medium. **Falsification condition:** The inference is false if activation rules make these skills mutually unreachable or enforced host limits impose a finite agent count and recursion depth.

3. **GPT-5.6 inference** — Likely secret material may be exposed to executable or network-capable components if the flagged files and capabilities share a runtime boundary. Supporting evidence: `PHA-SECRET-001` in `.mcp.json` and `config/example.env`; `PHA-MCP-001` in `.mcp.json`; `PHA-EXEC-001` and `PHA-NET-001` in `hooks.json` and `scripts/risky-examples.txt`. **Confidence:** Medium. **Falsification condition:** The inference is false if the flagged values are non-sensitive or inaccessible to every component with execution or network capability.

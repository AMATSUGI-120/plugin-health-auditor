# Architecture

Plugin Health Auditor uses one evidence model across three surfaces:

1. `src/audit.mjs` performs a deterministic, read-only scan.
2. `src/cli.mjs`, `src/server.mjs`, and `mcp/server.mjs` expose the same report.
3. The bundled `audit-plugin-health` skill can direct an explicitly configured host Codex task running GPT-5.6 to review only the collected evidence, identify semantic conflicts, and clearly separate deterministic findings from model inferences. The scanner and MCP server only prepare evidence; they do not call or pin a model.

## Trust boundary

The scanner treats every target file as untrusted input. Discovered symlinks are skipped. Reads use `O_NOFOLLOW` where available, plus opened-handle stat and post-open root checks; these measures narrow but cannot eliminate every mutable-filesystem race. It never executes target scripts, imports target modules, installs dependencies, or sends content over the network.

## Report contract

Every finding must include a stable rule ID, severity, category, summary, file path, line number when available, evidence excerpt, and remediation. Aggregate scores are derived from finding severity and are not presented as observed token usage or billing cost.

## Current verification snapshot

- Unsafe fixture: 11 findings across 9 files; 6 high, 5 medium; score `57`; risk `high`; 2,838 estimated context tokens.
- Self-audit: 0 findings.
- Automated tests: 16 passing, including HTTP coverage for health, successful audit, malformed JSON, oversized body, missing path, and generic internal errors.

## MCP configuration

The current `.mcp.json` is a direct server map, supported by the current official Codex plugin docs. It exposes the local MCP transport and does not select, call, or pin a model.

## Model roles

- Deterministic scanner: inventory, pattern matching, approximate token counts, manifest checks, and evidence extraction.
- Host Codex task explicitly configured to GPT-5.6: separately labeled semantic inferences about instruction conflicts, scope mismatch, amplification chains, native-feature overlap, and prioritization, grounded in scanner evidence.
- Human reviewer: accepts or rejects model inferences and decides whether configuration should change.

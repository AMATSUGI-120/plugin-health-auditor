# Architecture

Plugin Health Auditor uses one evidence model across three surfaces:

1. `src/audit.mjs` performs a deterministic, read-only scan.
2. `src/cli.mjs`, `src/server.mjs`, and `mcp/server.mjs` expose the same report.
3. The bundled `audit-plugin-health` skill can direct an explicitly configured host Codex task running GPT-5.6 to review only the collected evidence, identify semantic conflicts, and clearly separate deterministic findings from model inferences. The scanner and MCP server only prepare evidence; they do not call or pin a model.

## Trust boundary

The scanner treats every target file as untrusted input. Discovered symlinks are skipped. Reads use `O_NOFOLLOW` where available, plus opened-handle stat and post-open root checks; these measures narrow but cannot eliminate every mutable-filesystem race. It never executes target scripts, imports target modules, installs dependencies, or sends content over the network.

The browser API is a trusted-local-user convenience: a localhost caller selects the local audit path, and the server rejects non-local `Host` and browser `Origin` values. Audit POSTs require `application/json`, preventing simple cross-origin form or `text/plain` requests. These checks narrow cross-site misuse but are not authentication. The selected path is still untrusted data and is inspected read-only.

## Adversarial hardening

- Detector-shaped content, including a copied `PHA-EXEC-001` ID and pattern, cannot disable matching. Pattern-based rules emit only the first match per file and rule so evidence remains bounded.
- Scanner source self-exclusion is exact and path-based: only `path.resolve(file) === SCANNER_MODULE_REAL_PATH` is excluded, where `SCANNER_MODULE_REAL_PATH` is the real path resolved from the scanner module URL. A similarly named or copied file is still scanned.
- `dist/` and `build/` are supported scan locations. Skipped categories keep exact scalar counts and at most 100 relative path samples, including `ignoredDirectoriesCount` and `ignoredDirectories`.
- `PHA-EXFIL-001` is a high-severity, medium-confidence heuristic requiring any local file/environment signal and a nearby network call. A plain documentation URL or isolated `readFileSync` does not qualify, and an earlier unrelated read does not suppress a later qualifying pair.
- Skill recursion requires explicit self-skill syntax for every name. Ordinary prose such as “run build” is not recursive, and Markdown backticks are not treated as shell execution.

## Report contract

Every finding must include a stable rule ID, severity, category, summary, file path, line number when available, evidence excerpt, and remediation. Aggregate scores are derived from finding severity and are not presented as observed token usage or billing cost.

## Current verification snapshot

- Unsafe fixture: 11 findings across 9 files; 6 high, 5 medium; score `57`; risk `high`; 2,838 estimated context tokens.
- Self-audit: 0 findings.
- Automated tests: exactly 16 passing top-level tests, including adversarial scanner coverage, MCP parse-error hygiene and response ordering, plus HTTP host validation, health, successful audit, malformed JSON, oversized body, missing path, and generic internal errors.

## MCP configuration

The current `.mcp.json` is a direct server map, supported by the current official Codex plugin docs. It exposes the local MCP transport and does not select, call, or pin a model.

The stdio server processes bounded JSONL messages sequentially. Expected target-path failures return a generic tool result; unexpected failures return JSON-RPC `-32603 Internal error`, without filesystem or parser details.

## Model roles

- Deterministic scanner: inventory, pattern matching, approximate token counts, manifest checks, and evidence extraction.
- Host Codex task explicitly configured to GPT-5.6: separately labeled semantic inferences about instruction conflicts, scope mismatch, amplification chains, native-feature overlap, and prioritization, grounded in scanner evidence.
- Human reviewer: accepts or rejects model inferences and decides whether configuration should change.

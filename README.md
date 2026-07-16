# Plugin Health Auditor

Plugin Health Auditor is a small, zero-dependency Node.js tool for checking Codex plugins and Agent Skills before they become part of a working context. It was built for OpenAI Build Week by Social Hub.

![Plugin Health Auditor showing an evidence-backed unsafe fixture report](assets/plugin-health-auditor-results.jpg)

## The problem

An agent stack can look harmless while combining always-on instructions, oversized skills, recursive calls, unbounded subagents, executable hooks, network access, broad MCP permissions, or exposed secrets. Those risks are easy to miss when reviewing files one at a time.

## Evidence before inference

The scanner reads a bounded set of local text and manifest files and emits stable rule IDs, severity, category, file, line, evidence, and remediation. It redacts likely secrets in evidence. Deterministic findings come first. The scanner and MCP server only prepare evidence; they do not call or pin a model. When the host Codex task is explicitly configured to GPT-5.6, the bundled skill instructs that host model to review interactions such as scope conflicts, amplification chains, and native-feature overlap. Those separately labeled GPT-5.6 observations are inferences, not scanner facts, and should cite their evidence and confidence.

## Features

- Read-only inventory and deterministic pattern checks for plugins, skills, prompts, hooks, scripts, and MCP manifests.
- Checks for always-on language, recursive invocation, subagent amplification, oversized instruction files, execution, network access, possible exfiltration, secrets, broad permissions, malformed manifests, scan limits, and symlink boundaries.
- Text and JSON CLI reports, a local browser demo, and an MCP server exposing `audit_plugin_health` and `prepare_semantic_review`.
- Stable findings and a severity-weighted score for triage; the score is not a security certification.
- Synthetic safe and unsafe fixtures for repeatable judge testing.

## Architecture

`src/audit.mjs` is the single deterministic audit engine. `src/cli.mjs`, `src/server.mjs`, and `mcp/server.mjs` expose the same report. The bundled `skills/audit-plugin-health/SKILL.md` directs Codex to run the scanner and treat target content as untrusted data. The scanner and MCP server prepare an evidence packet; if the host Codex task is explicitly running GPT-5.6, the skill directs that host model to review it and label semantic inferences separately. A human remains responsible for accepting or rejecting those inferences.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the report contract and trust boundary.
See [docs/SEMANTIC_REVIEW_EXAMPLE.md](docs/SEMANTIC_REVIEW_EXAMPLE.md) for a review generated in a host task explicitly configured as `gpt-5.6-sol`.
See [docs/SUBMISSION_CHECKLIST.md](docs/SUBMISSION_CHECKLIST.md) for the verified Build Week handoff and remaining external actions.

## Quickstart

Requires Node.js 20 or newer. The project has no runtime or development dependencies, so no install step is required.

```bash
cd plugin-health-auditor
node --version
node src/cli.mjs . --format text
```

JSON output and file output:

```bash
node src/cli.mjs . --format json
node src/cli.mjs . --format json --output audit.json
```

Supported platforms are macOS, Linux, and Windows with Node.js 20+. On Windows, run the same commands from PowerShell or Command Prompt; use the platform's path syntax for the target.

## Demo and MCP

Start the local browser demo:

```bash
npm run demo
```

The server listens on `http://127.0.0.1:4173` by default. It also provides `GET /health` and `POST /api/audit` with a JSON body such as `{"path":"test/fixtures/unsafe-plugin"}`.
Malformed JSON returns `400`, request bodies over 1 MiB return `413`, and audit failures return a generic `500` response without exposing filesystem details.

Start the stdio MCP server:

```bash
npm run mcp
```

The MCP tools are `audit_plugin_health` for a deterministic report and `prepare_semantic_review` for a compact evidence packet. The current [.mcp.json](.mcp.json) is a direct server map, the format supported by the current official Codex plugin docs; MCP prepares evidence but does not call or pin GPT-5.6.

## Tests and checks

```bash
npm test
npm run check
```

The automated suite currently reports 16 passing tests covering stable safe/unsafe findings, evidence paths and line numbers, redaction, symlink handling, CLI JSON and exit behavior, MCP initialization/tool output, and HTTP health, successful audit, malformed JSON, oversized body, missing path, and generic internal errors.

## Trust boundary

The auditor treats every target file as untrusted input. Discovered symlinks are skipped. Reads use `O_NOFOLLOW` where available, plus opened-handle stat and post-open root checks; these measures narrow but cannot eliminate every mutable-filesystem race. The auditor does not execute target code, import target modules, install dependencies, enable or repair target configuration, or send target content over the network. An audit authorizes inspection only; remediation requires a separate decision.

## Token estimate disclaimer

Reports include `estimatedTokens`, calculated as characters divided by four. This is a deterministic sizing estimate, not observed model usage, context consumption, billing, or guaranteed savings. Never convert it into currency without an explicit usage and pricing scenario.

## Codex and GPT-5.6 collaboration

Codex orchestrates the read-only workflow and preserves the evidence contract. The deterministic scanner and MCP server supply facts and evidence packets; neither independently invokes or pins a model. When a host Codex task is explicitly running GPT-5.6, the bundled skill instructs that host model to label conclusions as `GPT-5.6 inference`, cite supporting rule IDs or files, assign confidence, and state a falsification condition. Codex presents both layers separately for human review.

## Judge testing path

From the repository checkout, use the existing unsafe fixture directly; do not rebuild it:

```bash
cd plugin-health-auditor
node src/cli.mjs test/fixtures/unsafe-plugin --format text
npm test
```

The fixture is synthetic and intentionally unsafe. The verified snapshot reports 11 findings: 6 high and 5 medium, score `57`, risk level `high`, across 9 files, with 2,838 estimated context tokens and redacted secret evidence. A self-audit reports 0 findings, and the automated suite reports 16 passing tests. Exact timestamps and absolute target paths vary. The fixture is for testing the auditor, not for execution.

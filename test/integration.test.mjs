import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { createAuditServer } from "../src/server.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "src", "cli.mjs");
const SAFE = join(ROOT, "test", "fixtures", "safe-plugin");
const UNSAFE = join(ROOT, "test", "fixtures", "unsafe-plugin");

async function startAuditServer(t) {
  const server = createAuditServer();
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("error", onError);
      reject(error);
    };
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

test("GET /health returns service status", async (t) => {
  const baseUrl = await startAuditServer(t);
  const response = await fetch(`${baseUrl}/health`);

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true, service: "plugin-health-auditor" });
});

test("POST /api/audit returns the deterministic unsafe fixture summary", async (t) => {
  const baseUrl = await startAuditServer(t);
  const response = await fetch(`${baseUrl}/api/audit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ path: UNSAFE })
  });

  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).summary, {
    findings: 11,
    bySeverity: { info: 0, low: 0, medium: 5, high: 6, critical: 0 },
    score: 57,
    riskLevel: "high",
    scoreDescription: "Severity-weighted deterministic finding score; not a security rating or token/billing measure."
  });
});

test("POST /api/audit rejects malformed JSON without parser details", async (t) => {
  const baseUrl = await startAuditServer(t);
  const response = await fetch(`${baseUrl}/api/audit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{"
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "Invalid JSON request body" });
});

test("POST /api/audit rejects bodies over 1 MiB", async (t) => {
  const baseUrl = await startAuditServer(t);
  const response = await fetch(`${baseUrl}/api/audit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ path: "a".repeat(1_048_576) })
  });

  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { error: "Request body too large" });
});

test("POST /api/audit requires a path", async (t) => {
  const baseUrl = await startAuditServer(t);
  for (const body of ["{}", "null", "[]"]) {
    const response = await fetch(`${baseUrl}/api/audit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body
    });

    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "A non-empty path is required" });
  }
});

test("POST /api/audit hides nonexistent target details", async (t) => {
  const baseUrl = await startAuditServer(t);
  const missingTarget = join(ROOT, "test", "fixtures", "does-not-exist");
  const response = await fetch(`${baseUrl}/api/audit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ path: missingTarget })
  });

  assert.equal(response.status, 500);
  assert.deepEqual(await response.json(), { error: "Internal server error" });
});

test("CLI uses documented exit codes and emits parseable JSON", () => {
  const safe = spawnSync(process.execPath, [CLI, SAFE, "--format", "json"], { encoding: "utf8" });
  assert.equal(safe.status, 0, safe.stderr);
  assert.equal(JSON.parse(safe.stdout).summary.riskLevel, "low");

  const unsafe = spawnSync(process.execPath, [CLI, UNSAFE, "--format", "json"], { encoding: "utf8" });
  assert.equal(unsafe.status, 1, unsafe.stderr);
  assert.equal(JSON.parse(unsafe.stdout).summary.riskLevel, "high");

  const invalid = spawnSync(process.execPath, [CLI], { encoding: "utf8" });
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /target path is required/i);
});

test("MCP config is a direct server map and its declared server validates protocol requests", async (t) => {
  const config = JSON.parse(await readFile(join(ROOT, ".mcp.json"), "utf8"));
  assert.equal(Object.hasOwn(config, "mcpServers"), false, "Codex MCP config must be a direct server map");
  const server = config["plugin-health-auditor"];
  assert.ok(server && typeof server.command === "string");
  assert.ok(Array.isArray(server.args));
  assert.equal(typeof server.cwd, "string");

  const child = spawn(server.command, server.args, { cwd: resolve(ROOT, server.cwd), stdio: ["pipe", "pipe", "pipe"] });
  t.after(() => child.kill("SIGTERM"));

  const messages = [];
  let pending = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    pending += chunk;
    const lines = pending.split("\n");
    pending = lines.pop() ?? "";
    for (const line of lines) if (line.trim()) messages.push(JSON.parse(line));
  });

  const send = (value) => child.stdin.write(`${JSON.stringify(value)}\n`);
  const sendRaw = (value) => child.stdin.write(`${value}\n`);
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } } });
  send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "audit_plugin_health", arguments: { path: SAFE } } });
  sendRaw('{"jsonrpc":');
  send("not a request");
  send({ jsonrpc: "2.0", id: 4, method: "missing/method", params: {} });
  send({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "not_a_tool", arguments: { path: SAFE } } });
  send({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "audit_plugin_health", arguments: { path: 12 } } });
  send({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "audit_plugin_health", arguments: { path: join(ROOT, "missing-target") } } });

  const deadline = Date.now() + 5_000;
  while (messages.length < 9 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  assert.equal(messages.length, 9);
  const byId = new Map(messages.filter((message) => message.id !== null).map((message) => [message.id, message]));
  assert.equal(byId.get(1).result.serverInfo.name, "plugin-health-auditor");
  assert.deepEqual(byId.get(2).result.tools.map((tool) => tool.name), ["audit_plugin_health", "prepare_semantic_review"]);
  assert.ok(byId.get(2).result.tools.every((tool) => tool.annotations?.readOnlyHint === true));
  assert.equal(byId.get(3).result.structuredContent.summary.riskLevel, "low");
  assert.equal(byId.get(3).result.isError, false);
  assert.equal(byId.get(4).error.code, -32601);
  assert.equal(byId.get(5).error.code, -32602);
  assert.equal(byId.get(6).error.code, -32602);
  assert.equal(byId.get(7).result.isError, true, "audit failures are tool results, not protocol errors");
  const nullErrors = messages.filter((message) => message.id === null).map((message) => message.error.code).sort();
  assert.deepEqual(nullErrors, [-32600, -32700], "valid JSON with an invalid request must not be called a parse error");
});

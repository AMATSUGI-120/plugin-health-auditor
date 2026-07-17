#!/usr/bin/env node

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { auditPath } from "./audit.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const indexPath = join(here, "../web/index.html");
const host = "127.0.0.1";
const port = Number.parseInt(process.env.PORT || "4173", 10);
const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024;

class InvalidJsonError extends Error {}
class RequestBodyTooLargeError extends Error {}

function json(response, status, body) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

function allowedHost(hostHeader) {
  if (typeof hostHeader !== "string") return false;
  const host = hostHeader.toLowerCase();
  if (/^(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(host)) return true;
  return /^\[::1\](?::\d+)?$/.test(host) || host === "::1";
}

function allowedOrigin(originHeader) {
  if (originHeader === undefined) return true;
  if (typeof originHeader !== "string") return false;
  try {
    const origin = new URL(originHeader);
    return (origin.protocol === "http:" || origin.protocol === "https:") && allowedHost(origin.host);
  } catch {
    return false;
  }
}

function isJsonRequest(request) {
  const contentType = request.headers["content-type"];
  return typeof contentType === "string" && contentType.split(";", 1)[0].trim().toLowerCase() === "application/json";
}

async function readJson(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_REQUEST_BODY_BYTES) throw new RequestBodyTooLargeError();
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw new InvalidJsonError();
  }
}

export function createAuditServer() {
  return createServer(async (request, response) => {
    try {
      if (!allowedHost(request.headers.host)) {
        json(response, 403, { error: "Forbidden" });
        return;
      }
      if (request.method === "GET" && request.url === "/") {
        const html = await readFile(indexPath);
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY"
        });
        response.end(html);
        return;
      }

      if (request.method === "GET" && request.url === "/health") {
        json(response, 200, { ok: true, service: "plugin-health-auditor" });
        return;
      }

      if (request.method === "POST" && request.url === "/api/audit") {
        if (!allowedOrigin(request.headers.origin)) {
          json(response, 403, { error: "Forbidden" });
          return;
        }
        if (!isJsonRequest(request)) {
          json(response, 415, { error: "Content-Type must be application/json" });
          return;
        }
        const body = await readJson(request);
        if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.path !== "string" || !body.path.trim()) {
          json(response, 400, { error: "A non-empty path is required" });
          return;
        }
        json(response, 200, await auditPath(body.path));
        return;
      }

      json(response, 404, { error: "Not found" });
    } catch (cause) {
      if (cause instanceof InvalidJsonError) {
        json(response, 400, { error: "Invalid JSON request body" });
        return;
      }
      if (cause instanceof RequestBodyTooLargeError) {
        json(response, 413, { error: "Request body too large" });
        return;
      }
      json(response, 500, { error: "Internal server error" });
    }
  });
}

export function startServer(listenPort = port) {
  const server = createAuditServer();
  server.listen(listenPort, host, () => {
    process.stdout.write(`Plugin Health Auditor demo: http://${host}:${listenPort}\n`);
  });
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) startServer();

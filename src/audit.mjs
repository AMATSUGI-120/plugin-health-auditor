import { constants as FS_CONSTANTS } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULTS = Object.freeze({ maxFiles: 2_000, maxFileBytes: 512 * 1024, maxTotalBytes: 10 * 1024 * 1024 });
const LIMITS = Object.freeze({ maxFiles: 10_000, maxFileBytes: 2 * 1024 * 1024, maxTotalBytes: 50 * 1024 * 1024 });
const IGNORED_DIRECTORIES = new Set(['.git', '.hg', '.svn', 'node_modules', 'vendor', 'coverage', '.next', 'test']);
const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.py', '.rb', '.php', '.go', '.rs', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.json', '.md', '.txt']);
const SEVERITY_POINTS = Object.freeze({ info: 0, low: 1, medium: 3, high: 7, critical: 12 });
const SKIPPED_PATH_LIMIT = 100;
const SCANNER_MODULE_REAL_PATH = await fsp.realpath(fileURLToPath(import.meta.url));
const SHELL_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.fish']);
const SECRET_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/g,
  /\b(?:xox[baprs]|AIza)[A-Za-z0-9_-]{16,}\b/g,
  /\b(?:api[_-]?key|token|secret|password|passwd|access[_-]?key)\s*[:=]\s*(['"]?)[^\s,'";]{8,}\1/gi,
];

function bounded(value, fallback, maximum) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? Math.min(Math.floor(numeric), maximum) : fallback;
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function relativeFile(root, file) {
  const relative = path.relative(root, file);
  return relative || path.basename(file);
}

function isCandidate(file) {
  const base = path.basename(file);
  if (base === 'SKILL.md' || base === 'plugin.json' || base === '.mcp.json') return true;
  if (base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) return true;
  if (file.split(path.sep).includes('hooks')) return true;
  return TEXT_EXTENSIONS.has(path.extname(base).toLowerCase());
}

function displayEvidence(line) {
  let value = String(line).replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  for (const pattern of SECRET_PATTERNS) value = value.replace(pattern, '[REDACTED]');
  value = value.replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@');
  return value.length > 220 ? `${value.slice(0, 217)}...` : value;
}

function lineAt(text, index) {
  return text.slice(0, index).split('\n').length;
}

function excerptAt(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  const end = text.indexOf('\n', index);
  return displayEvidence(text.slice(start, end === -1 ? text.length : end));
}

function finding(ruleId, severity, category, summary, file, line, evidence, remediation, confidence = 'high') {
  return { ruleId, severity, category, summary, file, line: line || null, evidence: displayEvidence(evidence || ''), remediation, confidence, source: 'deterministic' };
}

export class AuditTargetError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuditTargetError';
  }
}

function addPatternFindings(findings, file, text, rules, excludeSelf = false) {
  if (excludeSelf) return;
  for (const rule of rules) {
    const match = rule.pattern.exec(text);
    if (!match) continue;
    const evidence = excerptAt(text, match.index);
    findings.push(finding(rule.id, rule.severity, rule.category, rule.summary, file, lineAt(text, match.index), evidence, rule.remediation, rule.confidence));
  }
}

function isShellLike(file) {
  return SHELL_EXTENSIONS.has(path.extname(file).toLowerCase());
}

function addExfiltrationFinding(findings, relative, text, excludeSelf) {
  if (excludeSelf) return;
  const sensitiveMatches = [...text.matchAll(/\b(?:process\.env\b|(?:fs\.)?readFile(?:Sync)?\s*\()/gi)];
  const networkMatches = [...text.matchAll(/\b(?:fetch|axios(?:\.[A-Za-z]+)?|https?\.(?:request|get)|WebSocket)\s*\(|(?:^|[|;&]\s*|\b(?:command|sudo)\s+)(?:curl|wget)\b/gim)];
  const shellSensitiveUpload = /(?:^|[|;&]\s*|\b(?:command|sudo)\s+)(?:curl|wget)\b[^\n]*(?:\$\{?[^\s}:]*(?:token|secret|key|env|home)[^\s}:]*\}?|\$\([^\n]*\bcat\b)/im;
  let sensitiveIndex = 0;
  let networkIndex = 0;
  let firstPairIndex = Number.POSITIVE_INFINITY;
  while (sensitiveIndex < sensitiveMatches.length && networkIndex < networkMatches.length) {
    const sensitive = sensitiveMatches[sensitiveIndex].index;
    const network = networkMatches[networkIndex].index;
    if (Math.abs(sensitive - network) <= 280) firstPairIndex = Math.min(firstPairIndex, sensitive, network);
    if (sensitive <= network) sensitiveIndex += 1;
    else networkIndex += 1;
  }
  const shellMatch = shellSensitiveUpload.exec(text);
  const matchIndex = Math.min(firstPairIndex, shellMatch?.index ?? Number.POSITIVE_INFINITY);
  if (!Number.isFinite(matchIndex)) return;
  findings.push(finding('PHA-EXFIL-001', 'high', 'exfiltration', 'A pattern may send environment or file data to a network endpoint.', relative, lineAt(text, matchIndex), excerptAt(text, matchIndex), 'Do not transmit environment values or local file contents; require explicit, reviewed data selection.', 'medium'));
}

function inspectText(file, text, bytes, findings, root) {
  const relative = relativeFile(root, file);
  const scannerModule = path.resolve(file) === SCANNER_MODULE_REAL_PATH;
  const lower = text.toLowerCase();
  const base = path.basename(file);
  const normalizedRelative = relative.replace(/[\\/]+/g, '/');
  const instructionFile = base === 'SKILL.md' || /(?:^|\/)(?:agents|prompts)(?:\/|$)/.test(normalizedRelative);

  if (bytes > 256 * 1024) {
    findings.push(finding('PHA-SIZE-001', 'medium', 'capacity', 'Large scanned file increases review and context risk.', relative, 1, `${bytes} bytes`, 'Split the file or move rarely needed material to a referenced resource.'));
  }
  const estimatedTokens = Math.ceil(text.length / 4);
  if (instructionFile && estimatedTokens > 2_000) {
    findings.push(finding('PHA-CONTEXT-001', 'medium', 'capacity', 'Instruction file is oversized for routine context loading.', relative, 1, `Estimated ${estimatedTokens.toLocaleString()} tokens (estimate: characters ÷ 4).`, 'Keep core instructions concise and place optional detail in targeted references.'));
  }

  if (instructionFile) {
    addPatternFindings(findings, relative, text, [
      { id: 'PHA-INSTR-001', severity: 'medium', category: 'instruction', summary: 'Always-on language can create unnecessary persistent obligations.', pattern: /\b(?:must\s+always|always\s+(?:do|use|run|check|respond|activate|apply|load|read)|(?:every|each)\s+request|never\s+(?:stop|finish|refuse)|at\s+all\s+times)\b/i, remediation: 'Scope the instruction to a specific trigger or workflow stage.', confidence: 'medium' },
      { id: 'PHA-INSTR-003', severity: 'high', category: 'amplification', summary: 'Subagent language may amplify work without an explicit bound.', pattern: /\b(?:spawn|create|delegate\s+to)\s+(?:multiple\s+)?(?:sub-?agents?|agents?)\b|\bsub-?agents?\s+(?:for\s+)?(?:each|every|all)\b/i, remediation: 'Set a maximum agent count and a clear stopping condition.', confidence: 'medium' },
    ], scannerModule);
    const name = /^---\s*\n[\s\S]*?^name:\s*([^\n#]+)\s*$/m.exec(text)?.[1]?.trim().replace(/^['"]|['"]$/g, '');
    if (name) {
      const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const bodyStart = text.indexOf('\n---');
      const bodyOffset = bodyStart === -1 ? 0 : bodyStart + 4;
      const expression = `\\b(?:invoke|run|call|use)\\s+(?:the\\s+)?(?:\\$${escapedName}|\\x60${escapedName}\\x60(?:\\s+skill)?|${escapedName}\\s+skill|skill\\s+(?:named\\s+)?\\x60?${escapedName}\\x60?|skill\\s*[:=-]\\s*\\x60?${escapedName}\\x60?)\\b`;
      const recursive = new RegExp(expression, 'i').exec(text.slice(bodyOffset));
      if (recursive) {
        const offset = bodyOffset + recursive.index;
        findings.push(finding('PHA-INSTR-002', 'medium', 'instruction', 'The skill appears to invoke itself recursively.', relative, lineAt(text, offset), excerptAt(text, offset), 'Replace self-invocation with a bounded, non-recursive workflow.', 'high'));
      }
    }
  }

  const shellLike = isShellLike(file);
  addPatternFindings(findings, relative, text, [
    { id: 'PHA-EXEC-001', severity: 'high', category: 'execution', summary: 'Shell or process execution capability is present.', pattern: shellLike ? /\b(?:child_process|exec(?:File)?(?:Sync)?\s*\(|spawn(?:Sync)?\s*\(|fork\s*\(|Bun\.spawn|Deno\.Command|subprocess\.(?:run|Popen)|os\.system|(?:sh|bash|zsh|cmd|powershell)\s+-[A-Za-z]*c)(?![\w$])|\|\s*(?:sh|bash)\b|`(?:[^`\n]+)`/i : /\b(?:child_process|exec(?:File)?(?:Sync)?\s*\(|spawn(?:Sync)?\s*\(|fork\s*\(|Bun\.spawn|Deno\.Command|subprocess\.(?:run|Popen)|os\.system|(?:sh|bash|zsh|cmd|powershell)\s+-[A-Za-z]*c)(?![\w$])|\|\s*(?:sh|bash)\b/i, remediation: 'Avoid executing untrusted input; use allowlisted commands and argument arrays when execution is essential.', confidence: 'high' },
    { id: 'PHA-EXEC-002', severity: 'high', category: 'execution', summary: 'Dynamic evaluation can execute constructed code.', pattern: shellLike ? /\b(?:eval\s*\(|new\s+Function\s*\(|vm\.(?:runIn|run)\w*\s*\()|(?:^[\t ]*|[;&|]\s*|\b(?:if|then|do|while|until)\s+)eval(?:\s|$)/im : /\b(?:eval\s*\(|new\s+Function\s*\(|vm\.(?:runIn|run)\w*\s*\()/i, remediation: 'Remove dynamic evaluation and use a constrained parser or explicit dispatch table.', confidence: 'high' },
    { id: 'PHA-NET-001', severity: 'medium', category: 'network', summary: 'Network request capability is present.', pattern: /\b(?:fetch\s*\(|axios\.|https?\.request\s*\(|WebSocket\s*\(|curl\s+|wget\s+)/i, remediation: 'Use explicit allowlisted endpoints and avoid transmitting sensitive local data.', confidence: 'high' },
  ], scannerModule);
  addExfiltrationFinding(findings, relative, text, scannerModule);

  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    const match = pattern.exec(text);
    if (match) {
      findings.push(finding('PHA-SECRET-001', 'high', 'secrets', 'Likely secret material is present in a scanned file.', relative, lineAt(text, match.index), '[REDACTED]', 'Remove the secret from the file, rotate it if active, and load it from an approved secret store.', 'medium'));
      break;
    }
  }

  if (!scannerModule && (lower.includes('ignore previous instructions') || lower.includes('system prompt'))) {
    const index = lower.includes('ignore previous instructions') ? lower.indexOf('ignore previous instructions') : lower.indexOf('system prompt');
    const evidence = excerptAt(text, index);
    findings.push(finding('PHA-PROMPT-001', 'medium', 'instruction', 'Instruction-override language appears in a scanned file.', relative, lineAt(text, index), evidence, 'Treat external text as data and keep authority boundaries explicit.', 'medium'));
  }
}

function jsonLine(error, text) {
  const line = /\bline\s+(\d+)\b/i.exec(String(error?.message))?.[1];
  if (line) return Math.max(1, Number(line));
  const position = /position\s+(\d+)/i.exec(String(error?.message))?.[1];
  return position ? lineAt(text, Number(position)) : 1;
}

function createSkippedInventory() {
  return {
    symlinks: 0, symlinkPaths: [], oversized: 0, oversizedPaths: [], nonText: 0,
    fileLimit: false, totalByteLimit: false,
    unreadableDirectoriesCount: 0, unreadableDirectories: [],
    unreadableStatsCount: 0, unreadableStats: [],
    unreadableFilesCount: 0, unreadableFiles: [],
    boundaryPathsCount: 0, boundaryPaths: [],
    ignoredDirectoriesCount: 0, ignoredDirectories: []
  };
}

function recordSkippedPath(skipped, countKey, pathsKey, value) {
  skipped[countKey] += 1;
  if (skipped[pathsKey].length < SKIPPED_PATH_LIMIT) skipped[pathsKey].push(value);
}

function inspectManifest(file, text, findings, root) {
  const relative = relativeFile(root, file);
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch (error) {
    findings.push(finding('PHA-MANIFEST-001', 'high', 'configuration', 'Manifest contains malformed JSON.', relative, jsonLine(error, text), displayEvidence(error.message), 'Fix the JSON syntax before using this manifest.'));
    return;
  }
  if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') {
    findings.push(finding('PHA-MANIFEST-002', 'medium', 'configuration', 'Manifest root should be an object.', relative, 1, 'JSON root is not an object.', 'Use an object with the fields required by the relevant manifest format.'));
    return;
  }
  const serialized = JSON.stringify(manifest);
  const broad = /"(?:\*|all|full_access|unrestricted|allow_all)"/i.exec(serialized) || /"(?:permissions?|scopes?|tools?|capabilities?)"\s*:\s*(?:true|\[\s*"\*")/i.exec(serialized);
  if (broad) {
    const index = Math.max(0, serialized.indexOf(broad[0]));
    findings.push(finding('PHA-MCP-001', 'high', 'permissions', 'Manifest requests broad or wildcard MCP permissions.', relative, 1, displayEvidence(serialized.slice(index, index + 180)), 'Replace wildcard permissions with the minimum explicit tools, scopes, and hosts needed.', 'high'));
  }
  if (path.basename(file) === 'plugin.json' && (!manifest.name || typeof manifest.name !== 'string')) {
    findings.push(finding('PHA-MANIFEST-003', 'medium', 'configuration', 'Plugin manifest is missing a string name.', relative, 1, '{ "name": ... } is required.', 'Add a non-empty plugin name.'));
  }
  if (path.basename(file) === '.mcp.json') {
    const hasWrappedServers = Object.hasOwn(manifest, 'mcp_servers');
    const serverMap = hasWrappedServers ? manifest.mcp_servers : manifest;
    const unsupportedWrapper = Object.hasOwn(manifest, 'mcpServers') || Object.hasOwn(manifest, 'servers');
    const validMap = serverMap && !Array.isArray(serverMap) && typeof serverMap === 'object'
      && Object.keys(serverMap).length > 0
      && Object.values(serverMap).every((server) => server && !Array.isArray(server) && typeof server === 'object' && typeof server.command === 'string' && server.command.length > 0);
    if (unsupportedWrapper || !validMap) {
      const evidence = unsupportedWrapper
        ? 'Unsupported wrapper; use a direct server map or { "mcp_servers": { ... } }.'
        : hasWrappedServers
          ? 'mcp_servers must be a non-empty map of named server configurations.'
          : 'Expected a non-empty direct server map or { "mcp_servers": { ... } }.';
      findings.push(finding('PHA-MANIFEST-004', 'medium', 'configuration', 'MCP manifest has an unsupported or empty server configuration shape.', relative, 1, evidence, 'Use a direct map of server names to configurations, or wrap that map in mcp_servers.'));
    }
  }
}

async function collectFiles(root, limits) {
  const files = [];
  const skipped = createSkippedInventory();
  let totalBytes = 0;
  async function walk(directory) {
    let entries;
    try { entries = await fsp.readdir(directory, { withFileTypes: true }); } catch { recordSkippedPath(skipped, 'unreadableDirectoriesCount', 'unreadableDirectories', relativeFile(root, directory)); return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= limits.maxFiles) { skipped.fileLimit = true; return; }
      if (totalBytes >= limits.maxTotalBytes) { skipped.totalByteLimit = true; return; }
      const full = path.join(directory, entry.name);
      if (!isWithin(root, full)) continue;
      if (entry.isSymbolicLink()) {
        recordSkippedPath(skipped, 'symlinks', 'symlinkPaths', relativeFile(root, full));
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) {
          recordSkippedPath(skipped, 'ignoredDirectoriesCount', 'ignoredDirectories', relativeFile(root, full));
        } else await walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!isCandidate(full)) { skipped.nonText += 1; continue; }
      let stat;
      try { stat = await fsp.lstat(full); } catch { recordSkippedPath(skipped, 'unreadableStatsCount', 'unreadableStats', relativeFile(root, full)); continue; }
      if (stat.isSymbolicLink()) {
        recordSkippedPath(skipped, 'symlinks', 'symlinkPaths', relativeFile(root, full));
        continue;
      }
      if (stat.size > limits.maxFileBytes) { recordSkippedPath(skipped, 'oversized', 'oversizedPaths', relativeFile(root, full)); continue; }
      if (totalBytes + stat.size > limits.maxTotalBytes) { skipped.totalByteLimit = true; return; }
      totalBytes += stat.size;
      files.push({ path: full, bytes: stat.size });
    }
  }
  await walk(root);
  return { files, skipped, totalBytes };
}

function openedReadFlags() {
  // O_NOFOLLOW narrows the check/open race where supported; the later handle and
  // realpath checks still cannot claim to eliminate every filesystem race.
  return FS_CONSTANTS.O_RDONLY | (typeof FS_CONSTANTS.O_NOFOLLOW === 'number' ? FS_CONSTANTS.O_NOFOLLOW : 0);
}

async function readHandleLimited(handle, maxBytes) {
  const chunks = [];
  let position = 0;
  while (position <= maxBytes) {
    const size = Math.min(64 * 1024, maxBytes + 1 - position);
    const buffer = Buffer.allocUnsafe(size);
    const { bytesRead } = await handle.read(buffer, 0, size, position);
    if (!bytesRead) break;
    chunks.push(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return Buffer.concat(chunks, position);
}

async function secureRead(root, entry, maxBytes) {
  let handle;
  try {
    handle = await fsp.open(entry.path, openedReadFlags());
    const stat = await handle.stat();
    if (!stat.isFile()) return { status: 'unreadable' };
    if (stat.size > maxBytes) return { status: 'oversized' };
    const resolved = await fsp.realpath(entry.path);
    if (!isWithin(root, resolved)) return { status: 'boundary' };
    const content = await readHandleLimited(handle, maxBytes);
    if (content.length > maxBytes) return { status: 'oversized' };
    return { status: 'ok', text: content.toString('utf8'), bytes: content.length };
  } catch {
    return { status: 'unreadable' };
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export async function auditPath(targetPath, options = {}) {
  if (typeof targetPath !== 'string' || !targetPath.trim()) throw new AuditTargetError('Target path must be a non-empty string.');
  const limits = {
    maxFiles: bounded(options.maxFiles, DEFAULTS.maxFiles, LIMITS.maxFiles),
    maxFileBytes: bounded(options.maxFileBytes, DEFAULTS.maxFileBytes, LIMITS.maxFileBytes),
    maxTotalBytes: bounded(options.maxTotalBytes, DEFAULTS.maxTotalBytes, LIMITS.maxTotalBytes),
  };
  const selected = path.resolve(targetPath);
  let selectedStat;
  let resolvedTarget;
  try {
    selectedStat = await fsp.lstat(selected);
    resolvedTarget = await fsp.realpath(selected);
  } catch {
    throw new AuditTargetError('Target path does not exist or cannot be inspected.');
  }
  if (selectedStat.isSymbolicLink()) throw new AuditTargetError('Target path must not be a symbolic link.');
  const root = selectedStat.isDirectory() ? resolvedTarget : path.dirname(resolvedTarget);
  const files = [];
  let skipped;
  if (selectedStat.isFile()) {
    if (!isCandidate(selected)) throw new AuditTargetError('Target file is not a supported text, script, configuration, or manifest file.');
    skipped = createSkippedInventory();
    if (selectedStat.size > limits.maxFileBytes) {
      recordSkippedPath(skipped, 'oversized', 'oversizedPaths', relativeFile(root, selected));
    } else {
      files.push({ path: selected, bytes: selectedStat.size });
    }
  } else if (selectedStat.isDirectory()) {
    const collected = await collectFiles(root, limits);
    files.push(...collected.files);
    skipped = collected.skipped;
  } else {
    throw new AuditTargetError('Target path must be a regular file or directory.');
  }

  const findings = [];
  let estimatedTokens = 0;
  let scannedBytes = 0;
  let scannedFiles = 0;
  for (const entry of files) {
    const remainingBytes = limits.maxTotalBytes - scannedBytes;
    if (remainingBytes <= 0) { skipped.totalByteLimit = true; break; }
    const read = await secureRead(root, entry, Math.min(limits.maxFileBytes, remainingBytes));
    const relative = relativeFile(root, entry.path);
    if (read.status === 'oversized') {
      recordSkippedPath(skipped, 'oversized', 'oversizedPaths', relative);
      continue;
    }
    if (read.status === 'boundary') {
      recordSkippedPath(skipped, 'boundaryPathsCount', 'boundaryPaths', relative);
      continue;
    }
    if (read.status !== 'ok') {
      recordSkippedPath(skipped, 'unreadableFilesCount', 'unreadableFiles', relative);
      continue;
    }
    const { text } = read;
    scannedBytes += read.bytes;
    scannedFiles += 1;
    estimatedTokens += Math.ceil(text.length / 4);
    inspectText(entry.path, text, read.bytes, findings, root);
    if (path.basename(entry.path) === 'plugin.json' || path.basename(entry.path) === '.mcp.json') inspectManifest(entry.path, text, findings, root);
  }
  if (skipped.fileLimit || skipped.totalByteLimit) {
    const reason = skipped.fileLimit ? `file limit (${limits.maxFiles})` : `total byte limit (${limits.maxTotalBytes})`;
    findings.push(finding('PHA-SCAN-001', 'medium', 'coverage', 'Scan stopped at a configured safety bound; coverage is incomplete.', '.', null, reason, 'Reduce the target scope or raise the bound within the scanner safety limits.', 'high'));
  }
  const coverageFindings = [
    ['PHA-SCAN-002', skipped.oversized, 'Candidate file exceeded a per-file safety bound and was not scanned.', `Skipped ${skipped.oversized} oversized candidate file(s).`, 'Audit the omitted file separately or raise maxFileBytes within the scanner safety limits.'],
    ['PHA-SCAN-003', skipped.unreadableDirectoriesCount, 'Directory could not be listed; coverage is incomplete.', `Could not list ${skipped.unreadableDirectoriesCount} directory path(s).`, 'Restore read access and rerun the audit.'],
    ['PHA-SCAN-004', skipped.unreadableStatsCount, 'File metadata could not be read; coverage is incomplete.', `Could not stat ${skipped.unreadableStatsCount} candidate path(s).`, 'Restore access or audit the affected path separately.'],
    ['PHA-SCAN-005', skipped.unreadableFilesCount, 'Candidate file could not be read safely; coverage is incomplete.', `Could not read ${skipped.unreadableFilesCount} candidate file(s).`, 'Restore access and rerun the audit.'],
    ['PHA-SCAN-006', skipped.boundaryPathsCount, 'Candidate file failed the post-open root-boundary check; coverage is incomplete.', `Skipped ${skipped.boundaryPathsCount} path(s) outside the resolved audit root.`, 'Review the path separately and ensure it remains inside the audit root.']
  ];
  for (const [ruleId, count, summary, evidence, remediation] of coverageFindings) {
    if (count) findings.push(finding(ruleId, 'medium', 'coverage', summary, '.', null, evidence, remediation, 'high'));
  }
  for (const symlinkPath of skipped.symlinkPaths) {
    findings.push(finding('PHA-FS-001', 'low', 'filesystem', 'Symbolic link was skipped to preserve the audit root boundary.', symlinkPath, 1, 'Symlink skipped; its target was not read.', 'Review the link separately and include its destination as an explicit audit target if needed.', 'high'));
  }
  findings.sort((a, b) => a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0) || a.ruleId.localeCompare(b.ruleId));
  const counts = Object.fromEntries(Object.keys(SEVERITY_POINTS).map((severity) => [severity, findings.filter((item) => item.severity === severity).length]));
  const score = findings.reduce((sum, item) => sum + SEVERITY_POINTS[item.severity], 0);
  const riskLevel = counts.critical > 0 ? 'critical' : counts.high > 0 ? 'high' : counts.medium > 0 ? 'medium' : 'low';
  return {
    schemaVersion: '1.0', source: 'deterministic', target: resolvedTarget, scannedAt: new Date().toISOString(),
    limits, inventory: { scannedFiles, scannedBytes, estimatedTokens, tokenEstimateMethod: 'characters divided by 4; this is an approximation, not observed token usage or billing cost', skipped },
    summary: { findings: findings.length, bySeverity: counts, score, riskLevel, scoreDescription: 'Severity-weighted deterministic finding score; not a security rating or token/billing measure.' },
    findings,
  };
}

export function formatTextReport(report) {
  const lines = [
    'Plugin Health Auditor (deterministic)',
    `Target: ${report.target}`,
    `Scanned: ${report.inventory.scannedFiles} files, ${report.inventory.scannedBytes} bytes; estimated tokens: ${report.inventory.estimatedTokens} (characters ÷ 4 estimate)`,
    `Findings: ${report.summary.findings} | critical ${report.summary.bySeverity.critical}, high ${report.summary.bySeverity.high}, medium ${report.summary.bySeverity.medium}, low ${report.summary.bySeverity.low}, info ${report.summary.bySeverity.info}`,
    `Score: ${report.summary.score} (severity-weighted deterministic score; not a security rating or billing measure)`,
    '',
  ];
  if (!report.findings.length) lines.push('No deterministic findings.');
  for (const item of report.findings) {
    lines.push(`[${item.severity.toUpperCase()}] ${item.ruleId} ${item.file}${item.line ? `:${item.line}` : ''} — ${item.summary}`);
    if (item.evidence) lines.push(`  Evidence: ${item.evidence}`);
    lines.push(`  Remediation: ${item.remediation}`);
  }
  return `${lines.join('\n')}\n`;
}

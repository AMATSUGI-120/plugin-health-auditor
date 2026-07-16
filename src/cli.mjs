#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { auditPath, formatTextReport } from './audit.mjs';

function usage() {
  return 'Usage: node src/cli.mjs <path> [--format text|json] [--output file]';
}

function parseArgs(args) {
  let target;
  let format = 'text';
  let output;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--format') {
      format = args[++index];
      if (!format) throw new Error('--format requires text or json.');
    } else if (argument === '--output') {
      output = args[++index];
      if (!output) throw new Error('--output requires a file path.');
    } else if (argument.startsWith('-')) {
      throw new Error(`Unknown option: ${argument}`);
    } else if (!target) {
      target = argument;
    } else {
      throw new Error('Only one target path may be provided.');
    }
  }
  if (!target) throw new Error('A target path is required.');
  if (!['text', 'json'].includes(format)) throw new Error('--format must be text or json.');
  return { target, format, output };
}

async function main() {
  const { target, format, output } = parseArgs(process.argv.slice(2));
  const report = await auditPath(target);
  const rendered = format === 'json' ? `${JSON.stringify(report, null, 2)}\n` : formatTextReport(report);
  if (output) await fs.writeFile(path.resolve(output), rendered, 'utf8');
  else process.stdout.write(rendered);
  return report.summary.bySeverity.high + report.summary.bySeverity.critical > 0 ? 1 : 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  process.stderr.write(`${error?.message || String(error)}\n${usage()}\n`);
  process.exitCode = 2;
}

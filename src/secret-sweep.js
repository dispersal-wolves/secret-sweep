#!/usr/bin/env node
import childProcess from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {loadConfig, scanFiles, walk} from './scanner.js';

function usage() {
  console.log('Usage: secret-sweep <scan [path] | staged> [--format text|json] [--max-bytes N]');
}

function stagedFiles(root) {
  const output = childProcess.execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], {cwd: root});
  return output.toString('utf8').split('\0').filter(Boolean).map((file) => path.join(root, file)).filter((file) => fs.existsSync(file));
}

export function run(argv) {
  const command = argv[0];
  if (!['scan', 'staged'].includes(command)) {
    usage();
    return 2;
  }
  const formatIndex = argv.indexOf('--format');
  const format = formatIndex >= 0 ? argv[formatIndex + 1] : 'text';
  if (!['text', 'json'].includes(format)) {
    console.error('Format must be text or json.');
    return 2;
  }
  const maxIndex = argv.indexOf('--max-bytes');
  const maxBytes = maxIndex >= 0 ? Number(argv[maxIndex + 1]) : 2_000_000;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    console.error('--max-bytes must be a positive integer.');
    return 2;
  }
  const candidatePath = command === 'scan' && argv[1] && !argv[1].startsWith('--') ? argv[1] : '.';
  const root = path.resolve(command === 'staged' ? '.' : candidatePath);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    console.error(`Directory not found: ${root}`);
    return 2;
  }
  try {
    const config = loadConfig(root);
    const files = command === 'staged' ? stagedFiles(root) : walk(root, config.ignorePaths);
    const findings = scanFiles(root, files, config, maxBytes);
    if (format === 'json') {
      console.log(JSON.stringify({schema: 'dispersal-wolves/secret-sweep/v1', summary: {files: files.length, findings: findings.length}, findings}, null, 2));
    } else {
      for (const finding of findings) console.log(`[${finding.severity.toUpperCase()}] ${finding.file}:${finding.line}:${finding.column} ${finding.rule} ${finding.preview} (${finding.fingerprint})`);
      console.log(`${files.length} files scanned · ${findings.length} findings`);
    }
    return findings.length ? 1 : 0;
  } catch (error) {
    console.error(`Secret Sweep: ${error.message}`);
    return 2;
  }
}

if (import.meta.url === `file://${process.argv[1].replaceAll('\\', '/')}` || process.argv[1]?.endsWith('secret-sweep.js')) {
  process.exitCode = run(process.argv.slice(2));
}

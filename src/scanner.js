import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const RULES = [
  {name: 'private-key', severity: 'critical', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g},
  {name: 'aws-access-key', severity: 'high', regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g},
  {name: 'github-token', severity: 'high', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b/g},
  {name: 'slack-token', severity: 'high', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,200}\b/g},
  {name: 'generic-secret', severity: 'medium', regex: /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']?([^\s"']{12,})/gi},
];

const DEFAULT_IGNORES = ['.git', 'node_modules', 'target', 'dist', 'build', '.venv', '__pycache__'];

export function entropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let result = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

export function fingerprint(value) {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

export function redact(value) {
  if (value.length <= 8) return '[REDACTED]';
  return `${value.slice(0, 3)}…${value.slice(-3)}`;
}

function lineAndColumn(text, offset) {
  const before = text.slice(0, offset);
  const lines = before.split('\n');
  return {line: lines.length, column: lines.at(-1).length + 1};
}

export function scanText(text, file = '<memory>', ignoredFingerprints = new Set()) {
  const findings = [];
  for (const rule of RULES) {
    rule.regex.lastIndex = 0;
    for (const match of text.matchAll(rule.regex)) {
      const secret = match[1] ?? match[0];
      const id = fingerprint(secret);
      if (ignoredFingerprints.has(id)) continue;
      const position = lineAndColumn(text, match.index ?? 0);
      findings.push({...position, file, rule: rule.name, severity: rule.severity, fingerprint: id, preview: redact(secret)});
    }
  }
  const tokenPattern = /\b[A-Za-z0-9+/_=-]{24,200}\b/g;
  for (const match of text.matchAll(tokenPattern)) {
    if (entropy(match[0]) < 4.3) continue;
    const id = fingerprint(match[0]);
    if (ignoredFingerprints.has(id) || findings.some((item) => item.fingerprint === id)) continue;
    const position = lineAndColumn(text, match.index ?? 0);
    findings.push({...position, file, rule: 'high-entropy-token', severity: 'low', fingerprint: id, preview: redact(match[0])});
  }
  return findings;
}

export function isProbablyBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  return sample.includes(0);
}

export function loadConfig(root) {
  const configPath = path.join(root, '.secret-sweep.json');
  if (!fs.existsSync(configPath)) return {ignorePaths: [], ignoreFingerprints: []};
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  return {
    ignorePaths: Array.isArray(config.ignorePaths) ? config.ignorePaths : [],
    ignoreFingerprints: Array.isArray(config.ignoreFingerprints) ? config.ignoreFingerprints : [],
  };
}

function wildcardToRegex(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replaceAll('**', '::DOUBLE::').replaceAll('*', '[^/]*').replaceAll('::DOUBLE::', '.*');
  return new RegExp(`^${escaped}$`);
}

export function shouldIgnore(relative, configured = []) {
  const normalized = relative.split(path.sep).join('/');
  if (normalized.split('/').some((part) => DEFAULT_IGNORES.includes(part))) return true;
  return configured.some((pattern) => wildcardToRegex(pattern).test(normalized));
}

export function walk(root, configured = []) {
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute);
      if (shouldIgnore(relative, configured)) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) files.push(absolute);
    }
  };
  visit(root);
  return files;
}

export function scanFiles(root, files, config, maxBytes = 2_000_000) {
  const ignored = new Set(config.ignoreFingerprints);
  const findings = [];
  for (const file of files) {
    let stats;
    try { stats = fs.statSync(file); } catch { continue; }
    if (stats.size > maxBytes) continue;
    const buffer = fs.readFileSync(file);
    if (isProbablyBinary(buffer)) continue;
    findings.push(...scanText(buffer.toString('utf8'), path.relative(root, file).split(path.sep).join('/'), ignored));
  }
  return findings;
}

import assert from 'node:assert/strict';
import test from 'node:test';
import {entropy, fingerprint, scanText, shouldIgnore} from '../src/scanner.js';

test('finds and redacts known credentials', () => {
  const token = `ghp_${'A'.repeat(36)}`;
  const findings = scanText(`TOKEN=${token}`, 'sample.env');
  assert.equal(findings.some((item) => item.rule === 'github-token'), true);
  assert.equal(JSON.stringify(findings).includes(token), false);
});

test('fingerprint allowlist suppresses a finding', () => {
  const secret = `AKIA${'A'.repeat(16)}`;
  assert.equal(scanText(secret, 'x', new Set([fingerprint(secret)])).length, 0);
});

test('entropy distinguishes repeated from varied strings', () => {
  assert.ok(entropy('abcdefghijklmnopqrstuvwx012345') > entropy('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'));
});

test('ignores dependency and configured paths', () => {
  assert.equal(shouldIgnore('node_modules/x.js'), true);
  assert.equal(shouldIgnore('fixtures/example.txt', ['fixtures/**']), true);
});

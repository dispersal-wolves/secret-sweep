import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const cli = fileURLToPath(new URL('../src/secret-sweep.js', import.meta.url));
const secret = `AKIA${'B'.repeat(16)}`;

function repository() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-sweep-'));
  childProcess.execFileSync('git', ['init', '-q'], {cwd: root});
  return root;
}

function stage(root, file, content) {
  fs.mkdirSync(path.dirname(path.join(root, file)), {recursive: true});
  fs.writeFileSync(path.join(root, file), content);
  childProcess.execFileSync('git', ['add', file], {cwd: root});
}

function staged(cwd) {
  const result = childProcess.spawnSync(process.execPath, [cli, 'staged', '--format', 'json'], {cwd, encoding: 'utf8'});
  return {status: result.status, report: result.stdout ? JSON.parse(result.stdout) : null, stderr: result.stderr};
}

test('staged scans the index, not the working tree', () => {
  const root = repository();
  stage(root, 'config.txt', `key ${secret}\n`);
  fs.writeFileSync(path.join(root, 'config.txt'), 'clean\n');
  const result = staged(root);
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.report.findings[0].rule, 'aws-access-key');
});

test('staged ignores a secret that exists only in the working tree', () => {
  const root = repository();
  stage(root, 'config.txt', 'clean\n');
  fs.writeFileSync(path.join(root, 'config.txt'), `key ${secret}\n`);
  assert.equal(staged(root).status, 0);
});

test('staged honours ignorePaths and works from a subdirectory', () => {
  const root = repository();
  stage(root, '.secret-sweep.json', JSON.stringify({ignorePaths: ['fixtures/**']}));
  stage(root, 'fixtures/sample.txt', `key ${secret}\n`);
  stage(root, 'src/app.txt', `key ${secret}\n`);
  const result = staged(path.join(root, 'src'));
  assert.equal(result.status, 1, result.stderr);
  assert.deepEqual(result.report.findings.map((item) => item.file), ['src/app.txt']);
});

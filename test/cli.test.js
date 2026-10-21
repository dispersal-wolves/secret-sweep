import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const cli = fileURLToPath(new URL('../src/secret-sweep.js', import.meta.url));

function runCli(entry, args) {
  return childProcess.spawnSync(process.execPath, [entry, ...args], {encoding: 'utf8'});
}

test('runs when invoked by its own path', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-sweep-'));
  const result = runCli(cli, ['scan', directory]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /0 files scanned/);
});

test('runs when invoked through a symlinked bin, as npm installs it', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-sweep-'));
  const link = path.join(directory, 'secret-sweep');
  try {
    fs.symlinkSync(cli, link);
  } catch (error) {
    context.skip(`symlinks unavailable: ${error.code}`);
    return;
  }
  const result = runCli(link, ['scan', directory]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /files scanned/);
});

test('does not run the CLI when imported as a module', async () => {
  const before = process.exitCode;
  await import('../src/secret-sweep.js');
  assert.equal(process.exitCode, before);
});

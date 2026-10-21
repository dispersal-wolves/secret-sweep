import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const cli = fileURLToPath(new URL('../src/secret-sweep.js', import.meta.url));

function runCli(args) {
  return childProcess.spawnSync(process.execPath, [cli, ...args], {encoding: 'utf8'});
}

for (const args of [['--help'], ['-h'], ['scan', '--help']]) {
  test(`${args.join(' ')} prints usage and exits 0`, () => {
    const result = runCli(args);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Usage: secret-sweep/);
    assert.match(result.stdout, /--max-bytes/);
  });
}

test('an unknown command still prints usage and exits 2', () => {
  const result = runCli(['nope']);
  assert.equal(result.status, 2);
  assert.match(result.stdout, /Usage: secret-sweep/);
});

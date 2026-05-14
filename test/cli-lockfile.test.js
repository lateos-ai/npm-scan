import { test } from 'node:test';
import assert from 'assert/strict';
import { execSync } from 'child_process';

test('CLI: scan-lockfile --help shows all options', async () => {
  const out = execSync('node cli/cli.js scan-lockfile --help', { encoding: 'utf8' });
  assert(out.includes('--file'));
  assert(out.includes('--fail-on'));
  assert(out.includes('--watch'));
  assert(out.includes('--debounce'));
  assert(out.includes('--silent'));
  assert(out.includes('--monorepo'));
  assert(out.includes('--yarn'));
  assert(out.includes('--pnpm'));
});

test('CLI: scan-lockfile non-existent file exits with error', async () => {
  try {
    execSync('node cli/cli.js scan-lockfile -f /nonexistent/lock.json', { encoding: 'utf8', stdio: 'pipe' });
    assert.fail('should throw');
  } catch (e) {
    assert(e.status !== 0);
  }
});

test('CLI: scan-lockfile --debounce option accepted', async () => {
  const out = execSync('node cli/cli.js scan-lockfile --help', { encoding: 'utf8' });
  assert(out.includes('--debounce'));
});
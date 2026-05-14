import { test } from 'node:test';
import assert from 'assert/strict';

test('CLI: --help outputs usage information', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js --help', { encoding: 'utf8' });
  assert(out.includes('Usage'));
  assert(out.includes('scan'));
  assert(out.includes('report'));
  assert(out.includes('scan-lockfile'));
});

test('CLI: --version outputs version string', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js --version', { encoding: 'utf8' });
  assert(/^\d+\.\d+\.\d+\s*$/.test(out), `unexpected version format: "${out}"`);
});

test('CLI: scan with no target exits with error', async () => {
  const { execSync } = await import('child_process');
  try {
    execSync('node cli/cli.js scan', { encoding: 'utf8', stdio: 'pipe' });
    assert.fail('Should have thrown');
  } catch (e) {
    assert(e.status !== 0, 'non-zero exit code');
  }
});

test('CLI: scan non-existent package shows 404 error', async () => {
  const { execSync } = await import('child_process');
  try {
    execSync('node cli/cli.js scan this-package-does-not-exist-12345', { encoding: 'utf8', stdio: 'pipe' });
    assert.fail('Should have thrown');
  } catch (e) {
    assert(e.stderr.includes('not found'), `expected 404 error, got: ${e.stderr}`);
  }
});

test('CLI: scan-lockfile shows scanning message', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan-lockfile', { encoding: 'utf8', timeout: 5000 });
  assert(out.includes('Scanning lockfile') || out.includes('scanId'));
});

test('CLI: scan-lockfile --help mentions yarn/pnpm options', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan-lockfile --help', { encoding: 'utf8' });
  assert(out.includes('--yarn'), 'should mention --yarn');
  assert(out.includes('--pnpm'), 'should mention --pnpm');
  assert(out.includes('--monorepo'), 'should mention --monorepo');
});

test('CLI: scan-lockfile with custom path works', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan-lockfile -f tests/corpus/malicious/shai-hulud-lock.json', { encoding: 'utf8', timeout: 5000 });
  assert(out.includes('findings') || out.includes('totalDependencies') || out.includes('scanId'));
});

test('CLI: scan-lockfile parses yarn.lock', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan-lockfile -f test/fixtures/lockfiles/yarn.lock --silent', { encoding: 'utf8', timeout: 5000 });
  const data = JSON.parse(out);
  assert(data.totalDependencies > 0, `expected packages, got ${data.totalDependencies}`);
  assert(data.lockfileVersion === 2, `expected v2, got ${data.lockfileVersion}`);
});

test('CLI: scan-lockfile parses pnpm-lock.yaml', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan-lockfile -f test/fixtures/lockfiles/pnpm-lock.yaml --pnpm --silent', { encoding: 'utf8', timeout: 5000 });
  const data = JSON.parse(out);
  assert(data.totalDependencies > 0, `expected packages, got ${data.totalDependencies}`);
  assert(Number(data.lockfileVersion) === 6, `expected v6, got ${data.lockfileVersion}`);
});

test('CLI: scan-lockfile auto-detects yarn.lock', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan-lockfile -f test/fixtures/lockfiles/yarn.lock --silent', { encoding: 'utf8', timeout: 5000 });
  const data = JSON.parse(out);
  assert(data.totalDependencies > 0, 'auto-detect yarn should parse');
});

test('CLI: scan-lockfile auto-detects pnpm-lock.yaml', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan-lockfile -f test/fixtures/lockfiles/pnpm-lock.yaml --silent', { encoding: 'utf8', timeout: 5000 });
  const data = JSON.parse(out);
  assert(data.totalDependencies > 0, 'auto-detect pnpm should parse');
});

test('CLI: report shows recent scans message', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js report', { encoding: 'utf8', timeout: 5000 });
  assert(out.includes('Recent scans') || out.includes('scans'));
});

test('CLI: report with non-existent scan ID shows empty', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js report -i 999999', { encoding: 'utf8', timeout: 5000 });
  assert(out.includes('[]') || out.includes('No findings'));
});

test('CLI: report help text mentions report options', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js report --help', { encoding: 'utf8' });
  assert(out.includes('--sbom'));
  assert(out.includes('--html'));
  assert(out.includes('--text'));
  assert(out.includes('--siem'));
  assert(out.includes('--pdf'));
});

test('CLI: scan help text mentions policy option', async () => {
  const { execSync } = await import('child_process');
  const out = execSync('node cli/cli.js scan --help', { encoding: 'utf8' });
  assert(out.includes('--policy'));
  assert(out.includes('--sbom'));
  assert(out.includes('--license-key'));
});

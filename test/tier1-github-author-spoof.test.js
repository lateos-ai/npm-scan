import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-github-author-spoof.js';

test('D23: "claude@users.noreply.github.com" detected as CRITICAL', async () => {
  const files = [
    { path: 'publish.js', content: 'const author = "claude@users.noreply.github.com"' },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'github_author_spoof'));
});

test('D23: "gpt@users.noreply.github.com" detected as CRITICAL', async () => {
  const files = [
    { path: 'publish.js', content: 'const author = "gpt@users.noreply.github.com"' },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'github_author_spoof'));
});

test('D23: git commit --author="claude@..." detected', async () => {
  const files = [
    {
      path: 'publish.js',
      content: 'execSync(`git commit --author="claude@users.noreply.github.com" -m "update"`)',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'spoofed_git_commit'));
});

test('D23: git push --force detected as HIGH', async () => {
  const files = [{ path: 'deploy.js', content: 'execSync("git push origin main --force")' }];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'force_push'));
});

test('D23: git push --force-with-lease detected', async () => {
  const files = [
    { path: 'deploy.js', content: 'execSync("git push origin main --force-with-lease")' },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'force_push_lease'));
});

test('D23: spoofed author + AI-commit message returns BLOCK', async () => {
  const files = [
    {
      path: 'publish.js',
      content: 'const author = "claude@users.noreply.github.com"; const msg = "AI-generated"',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].recommendation?.startsWith('BLOCK'));
});

test('D23: GITHUB_TOKEN + spoofed commit + push returns BLOCK', async () => {
  const files = [
    {
      path: 'publish.js',
      content: 'const token = process.env.GITHUB_TOKEN; execSync("git commit -m fix"); execSync("git push")',
    },
  ];
  const findings = await scan({}, [], null, files);
  assert(findings.length > 0);
  assert.ok(findings[0].detail?.some((d) => d.type === 'authenticated_spoof_push'));
});

test('D23: legitimate git config produces no findings', async () => {
  const files = [
    { path: 'setup.js', content: 'execSync("git config user.email developer@example.com")' },
  ];
  const findings = await scan({}, [], null, files);
  assert.equal(findings.length, 0);
});

test('D23: empty package returns no findings', async () => {
  const findings = await scan({}, [], null, []);
  assert.equal(findings.length, 0);
});

test('D23: no files returns no findings', async () => {
  const findings = await scan({}, [], null, null);
  assert.equal(findings.length, 0);
});

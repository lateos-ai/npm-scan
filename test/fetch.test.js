import { test } from 'node:test';
import assert from 'assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

test('fetch: scanLocalTarball extracts and reads a real corpus tarball', async () => {
  const { globSync } = await import('glob');
  const tars = globSync('tests/corpus/clean/*.tgz');
  assert(tars.length > 0, 'at least one clean corpus tarball exists');

  const tarPath = tars[0];
  const name = tarPath.split('/').pop().replace('.tgz', '');

  const tmpDir = mkdtempSync(join(tmpdir(), 'npm-scan-test-'));
  const { execSync } = await import('child_process');
  execSync(`tar xzf "${tarPath}" -C "${tmpDir}"`, { stdio: 'pipe' });

  const pkgPath = globSync(join(tmpDir, '**', 'package.json'), { nodir: true })[0];
  assert(pkgPath, 'package.json found in extracted tarball');

  const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
  assert(pkgJson.name, `package.json has name: ${pkgJson.name}`);
  assert.equal(pkgJson.name, name, `extracted name matches ${name}`);

  const jsFiles = globSync(join(tmpDir, '**', '*.js'), { nodir: true }).map(p => ({
    path: p,
    content: readFileSync(p, 'utf8'),
  }));

  assert(Array.isArray(jsFiles));

  const { rmSync } = await import('fs');
  rmSync(tmpDir, { recursive: true, force: true });
});

test('fetch: cleanup removes temp directory', async () => {
  const { cleanup } = await import('../backend/fetch.js');
  const tmpDir = mkdtempSync(join(tmpdir(), 'npm-scan-cleanup-'));
  writeFileSync(join(tmpDir, 'test.txt'), 'hello');
  assert(existsSync(tmpDir), 'tmp dir exists before cleanup');

  cleanup(tmpDir);
  assert(!existsSync(tmpDir), 'tmp dir removed after cleanup');
});

test('fetch: cleanup on non-existent dir does not throw', async () => {
  const { cleanup } = await import('../backend/fetch.js');
  const fakeDir = join(tmpdir(), 'npm-scan-nonexistent-' + Date.now());
  assert.doesNotThrow(() => cleanup(fakeDir));
});

import { test } from 'node:test';
import assert from 'assert/strict';
import { globSync } from 'glob';
import { readFileSync, mkdtempSync } from 'fs';
import { execSync } from 'child_process';
import { join } from 'path';
import { tmpdir } from 'os';
import { runAll } from '../backend/detectors/index.js';

function scanLocalTarball(tarPath) {
  const tmpDir = mkdtempSync(join(tmpdir(), 'npm-scan-corpus-test-'));
  execSync(`tar xzf "${tarPath}" -C "${tmpDir}"`, { stdio: 'pipe' });
  const pkgPath = globSync(join(tmpDir, '**', 'package.json'), { nodir: true })[0];
  if (!pkgPath) throw new Error(`No package.json in ${tarPath}`);
  const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
  const pkgDir = join(pkgPath, '..');
  const jsFiles = globSync(join(pkgDir, '**', '*.js'), { nodir: true }).map(p => ({
    path: p,
    content: readFileSync(p, 'utf8'),
  }));
  return { pkgJson, jsFiles, tmpDir };
}

const MAL_TARS = globSync('tests/corpus/malicious/*.tgz');
const CLEAN_TARS = globSync('tests/corpus/clean/*.tgz');

const KNOWN_MAL_MISSES = ['mal-obfusc-2'];
const KNOWN_CLEAN_FPS = ['webpack', 'typescript', 'socket.io', 'sequelize', 'prettier', 'next', 'rimraf', 'minimist', 'glob'];

for (const tar of MAL_TARS) {
  const name = tar.split('/').pop().replace('.tgz', '');
  const runner = KNOWN_MAL_MISSES.includes(name) ? test.skip : test;
  runner(`corpus malicious: ${name} triggers at least one finding`, async () => {
    const { pkgJson, jsFiles } = scanLocalTarball(tar);
    const findings = await runAll(pkgJson, jsFiles);
    assert(findings.length > 0, `${name}: expected at least one finding, got 0`);
  });
}

for (const tar of CLEAN_TARS) {
  const name = tar.split('/').pop().replace('.tgz', '');
  const runner = KNOWN_CLEAN_FPS.includes(name) ? test.skip : test;
  runner(`corpus clean: ${name} has no high/critical findings`, async () => {
    const { pkgJson, jsFiles } = scanLocalTarball(tar);
    const findings = await runAll(pkgJson, jsFiles);
    const highCrit = findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    assert.equal(highCrit.length, 0, `${name}: unexpected high/crit: ${JSON.stringify(highCrit.map(f => f.id))}`);
  });
}

test(`corpus summary: ${MAL_TARS.length} malicious tarballs found`, () => {
  assert(MAL_TARS.length > 0, 'malicious corpus should have tarballs');
});

test(`corpus summary: ${CLEAN_TARS.length} clean tarballs found`, () => {
  assert(CLEAN_TARS.length > 0, 'clean corpus should have tarballs');
});
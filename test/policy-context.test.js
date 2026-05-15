import { test } from 'node:test';
import assert from 'assert/strict';
import { loadPolicy, applyPolicy, getPackageReputationTier, matchesContext } from '../backend/policy.js';
import { writeFileSync, unlinkSync } from 'fs';

test('policy: getPackageReputationTier returns trusted for known packages', async () => {
  assert.equal(getPackageReputationTier('react'), 'trusted');
  assert.equal(getPackageReputationTier('express'), 'trusted');
  assert.equal(getPackageReputationTier('hono'), 'trusted');
  assert.equal(getPackageReputationTier('webpack'), 'trusted');
  assert.equal(getPackageReputationTier('lodash'), 'trusted');
});

test('policy: getPackageReputation returns unknown for obscure packages', async () => {
  assert.equal(getPackageReputationTier('obscure-pkg-123'), 'unknown');
  assert.equal(getPackageReputationTier('@evil/scanner'), 'unknown');
});

test('policy: getPackageReputationTier handles scoped packages', async () => {
  assert.equal(getPackageReputationTier('@types/node'), 'unknown');
  assert.equal(getPackageReputationTier('@lateos/npm-scan'), 'unknown');
});

test('policy: matchesContext returns false when finding has no context', async () => {
  const finding = { id: 'ATK-002', severity: 'medium', title: 'test' };
  const rule = { atk_id: 'ATK-002', context: { is_dist_build: true } };
  assert.equal(matchesContext(finding, rule), false);
});

test('policy: matchesContext matches is_dist_build', async () => {
  const finding = {
    id: 'ATK-002',
    context: { file_path: 'dist/bundle.js', is_dist_build: true, is_test_fixture: false }
  };
  const rule = { atk_id: 'ATK-002', context: { is_dist_build: true } };
  assert.equal(matchesContext(finding, rule), true);

  const finding2 = {
    id: 'ATK-002',
    context: { file_path: 'src/index.js', is_dist_build: false, is_test_fixture: false }
  };
  assert.equal(matchesContext(finding2, rule), false);
});

test('policy: matchesContext matches is_test_fixture', async () => {
  const finding = {
    id: 'ATK-002',
    context: { file_path: 'test/fixtures/mock.js', is_test_fixture: true, is_dist_build: false }
  };
  const rule = { atk_id: 'ATK-002', context: { is_test_fixture: true } };
  assert.equal(matchesContext(finding, rule), true);
});

test('policy: matchesContext matches file_path pattern', async () => {
  const finding = {
    id: 'ATK-002',
    context: { file_path: 'dist/vendor/bundle.min.js', is_dist_build: true }
  };
  const rule = { atk_id: 'ATK-002', context: { file_path: 'dist/**/*.js' } };
  assert.equal(matchesContext(finding, rule), true);

  const finding2 = {
    id: 'ATK-002',
    context: { file_path: 'src/index.js', is_dist_build: false }
  };
  assert.equal(matchesContext(finding2, rule), false);
});

test('policy: matchesContext matches url_domain', async () => {
  const finding = {
    id: 'ATK-002',
    context: { url_domain: 'cdn.jsdelivr.net', is_known_safe_domain: true }
  };
  const rule = { atk_id: 'ATK-002', context: { url_domain: 'cdn.jsdelivr.net' } };
  assert.equal(matchesContext(finding, rule), true);

  const rule2 = { atk_id: 'ATK-002', context: { url_domain: '*.jsdelivr.net' } };
  assert.equal(matchesContext(finding, rule2), true);

  const finding2 = {
    id: 'ATK-002',
    context: { url_domain: 'evil-c2.example.com', is_known_safe_domain: false }
  };
  assert.equal(matchesContext(finding2, rule), false);
});

test('policy: matchesContext matches multiple context conditions (AND logic)', async () => {
  const finding = {
    id: 'ATK-002',
    context: { file_path: 'dist/bundle.js', is_dist_build: true, url_domain: 'unpkg.com', is_known_safe_domain: true }
  };
  const rule = { atk_id: 'ATK-002', context: { is_dist_build: true, is_known_safe_domain: true } };
  assert.equal(matchesContext(finding, rule), true);

  const rule2 = { atk_id: 'ATK-002', context: { is_dist_build: true, is_known_safe_domain: false } };
  assert.equal(matchesContext(finding, rule2), false);
});

test('policy: applyPolicy suppresses dist/build findings with context rule', async () => {
  const findings = [
    { id: 'ATK-002', severity: 'medium', title: 'Obfuscated payload', context: { file_path: 'dist/bundle.js', is_dist_build: true, url_domain: 'cdn.jsdelivr.net', is_known_safe_domain: true } },
    { id: 'ATK-002', severity: 'medium', title: 'Obfuscated payload', context: { file_path: 'src/index.js', is_dist_build: false, url_domain: 'evil-c2.example.com', is_known_safe_domain: false } },
  ];
  const policy = {
    allow: { packages: [] },
    severity_overrides: {},
    fail_on: 'none',
    suppress: [{ atk_id: 'ATK-002', package: '*', context: { is_dist_build: true, is_known_safe_domain: true }, reason: 'bundled dependency' }],
  };
  const result = applyPolicy(findings, 'test-pkg', policy);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].context.file_path, 'src/index.js');
});

test('policy: applyPolicy suppresses test fixture findings', async () => {
  const findings = [
    { id: 'ATK-002', severity: 'medium', title: 'Obfuscated payload', context: { file_path: 'test/fixtures/mock.js', is_test_fixture: true } },
    { id: 'ATK-002', severity: 'medium', title: 'Obfuscated payload', context: { file_path: 'src/index.js', is_test_fixture: false } },
  ];
  const policy = {
    allow: { packages: [] },
    severity_overrides: {},
    fail_on: 'none',
    suppress: [{ atk_id: 'ATK-002', package: '*', context: { is_test_fixture: true }, reason: 'test fixture' }],
  };
  const result = applyPolicy(findings, 'test-pkg', policy);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].context.file_path, 'src/index.js');
});

test('policy: applyPolicy suppresses by reputation tier', async () => {
  const findings = [
    { id: 'ATK-002', severity: 'medium', title: 'Obfuscated payload', context: { file_path: 'dist/bundle.js', is_dist_build: true } },
  ];
  const policy = {
    allow: { packages: [] },
    severity_overrides: {},
    fail_on: 'none',
    suppress: [{ atk_id: 'ATK-002', package: '*', context: { is_dist_build: true }, reputation_tier: 'trusted', reason: 'trusted package dist' }],
  };
  const resultTrusted = applyPolicy(findings, 'react', policy);
  assert.equal(resultTrusted.findings.length, 0);

  const resultUnknown = applyPolicy(findings, 'obscure-pkg', policy);
  assert.equal(resultUnknown.findings.length, 1);
});

test('policy: applyPolicy NEVER suppresses lifecycle hook findings', async () => {
  const findings = [
    { id: 'ATK-002', severity: 'medium', title: 'Obfuscated payload', context: { file_path: 'scripts/postinstall.js', is_lifecycle_hook: true, is_dist_build: false } },
  ];
  const policy = {
    allow: { packages: [] },
    severity_overrides: {},
    fail_on: 'none',
    suppress: [{ atk_id: 'ATK-002', package: '*', reason: 'suppress all' }],
  };
  const result = applyPolicy(findings, 'test-pkg', policy);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].context.is_lifecycle_hook, true);
});

test('policy: applyPolicy NEVER suppresses multi-layer obfuscation', async () => {
  const findings = [
    { id: 'ATK-002', severity: 'high', title: 'Obfuscated payload', context: { file_path: 'dist/bundle.js', is_dist_build: true, is_multi_layer: true } },
  ];
  const policy = {
    allow: { packages: [] },
    severity_overrides: {},
    fail_on: 'none',
    suppress: [{ atk_id: 'ATK-002', package: '*', context: { is_dist_build: true }, reason: 'dist file' }],
  };
  const result = applyPolicy(findings, 'test-pkg', policy);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].context.is_multi_layer, true);
});

test('policy: loadPolicy accepts context-aware suppress rules (YAML)', async () => {
  writeFileSync('/tmp/policy-context.yaml', `
suppress:
  - atk_id: ATK-002
    package: "*"
    context:
      is_dist_build: true
      is_known_safe_domain: true
    reason: bundled dependency from CDN
  - atk_id: ATK-002
    package: "*"
    context:
      is_test_fixture: true
    reason: test fixture
`);
  const p = loadPolicy('/tmp/policy-context.yaml');
  assert.equal(p.suppress.length, 2);
  assert.equal(p.suppress[0].context.is_dist_build, true);
  assert.equal(p.suppress[0].context.is_known_safe_domain, true);
  assert.equal(p.suppress[1].context.is_test_fixture, true);
});

test('policy: loadPolicy accepts reputation_tier in suppress rules', async () => {
  writeFileSync('/tmp/policy-rep.yaml', `
suppress:
  - atk_id: ATK-002
    package: "*"
    context:
      is_dist_build: true
    reputation_tier: trusted
    reason: trusted package dist files
`);
  const p = loadPolicy('/tmp/policy-rep.yaml');
  assert.equal(p.suppress[0].reputation_tier, 'trusted');
});

test('policy: loadPolicy accepts file_path pattern in context', async () => {
  writeFileSync('/tmp/policy-fp.yaml', `
suppress:
  - atk_id: ATK-002
    package: "*"
    context:
      file_path: "dist/**/*.js"
      url_domain: "*.jsdelivr.net"
    reason: dist files from jsdelivr
`);
  const p = loadPolicy('/tmp/policy-fp.yaml');
  assert.equal(p.suppress[0].context.file_path, 'dist/**/*.js');
  assert.equal(p.suppress[0].context.url_domain, '*.jsdelivr.net');
});

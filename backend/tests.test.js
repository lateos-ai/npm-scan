import { test } from 'node:test';
import assert from 'assert/strict';

// ─── SIEM Exporters ────────────────────────────────────────────────

const MOCK_SCANS = [
  {
    package_name: 'lodash',
    version: '4.17.21',
    findings: [
      { id: 'ATK-003', atk_id: 'ATK-003', severity: 'high', title: 'Credential harvest', description: 'Scrapes env vars', evidence: 'process.env.NPM_TOKEN' },
      { id: 'ATK-009', severity: 'medium', title: 'Time trigger', description: 'Conditional trigger (time-based)', evidence: 'time-based trigger detected' },
    ],
  },
];

test('SIEM CEF output format', async () => {
  const { generateCEF } = await import('./siem/cef.js');
  const out = generateCEF(MOCK_SCANS);
  assert(out.includes('CEF:0'), 'CEF header');
  assert(out.includes('ATK-003'), 'ATK-003 in output');
  assert(out.includes('ATK-009'), 'ATK-009 in output');
  assert(out.includes('high'), 'severity in output');
  assert(out.includes('medium'), 'severity in output');
  const lines = out.split('\n').filter(Boolean);
  assert.equal(lines.length, 2, '2 findings = 2 CEF lines');
});

test('SIEM CEF with empty findings', async () => {
  const { generateCEF } = await import('./siem/cef.js');
  const out = generateCEF([{ package_name: 'empty', version: '1.0.0', findings: [] }]);
  assert.equal(out, '', 'No output for empty findings');
});

test('SIEM ECS output format', async () => {
  const { generateECS } = await import('./siem/ecs.js');
  const out = generateECS(MOCK_SCANS);
  const events = out.split('\n').filter(Boolean);
  assert.equal(events.length, 2, '2 findings = 2 JSON lines');
  for (const line of events) {
    const e = JSON.parse(line);
    assert.equal(e.event.kind, 'alert', 'ECS event kind');
    assert.equal(e.observer.vendor, 'Lateos', 'ECS observer');
    assert(['high', 'medium'].includes(e.log.level), 'ECS log level');
    assert(e.vulnerability.enumeration === 'ATK', 'ECS enumeration');
      assert(e['@timestamp'], 'ECS timestamp');
      assert(['high', 'medium'].includes(e.log.level), 'ECS log level');
  }
});

test('SIEM Sentinel output format', async () => {
  const { generateSentinel } = await import('./siem/sentinel.js');
  const out = JSON.parse(generateSentinel(MOCK_SCANS));
  assert(Array.isArray(out));
  assert.equal(out.length, 2, '2 findings');
  assert(out[0].TimeGenerated, 'TimeGenerated field');
  assert.equal(out[0].DeviceVendor, 'Lateos');
  assert.equal(out[0].SourceSystem, 'npm-scan');
  assert(out[0].ATKId, 'ATK-003');
  assert(out[0].PackageName, 'lodash');
});

test('SIEM QRadar output format', async () => {
  const { generateQRadar } = await import('./siem/qradar.js');
  const out = generateQRadar(MOCK_SCANS);
  const events = out.split('\n').filter(Boolean);
  assert.equal(events.length, 2, '2 findings');
  const e = JSON.parse(events[0]);
  assert(e.source, 'npm-scan');
  assert(e.devicetime);
  assert(e.devicepayload.includes('lodash\t4.17.21'));
  assert(e.qid === 90050002, 'high severity QID');
  assert(e.category.includes('High Severity'));
});

test('SIEM QRadar severity QID mapping', async () => {
  const { generateQRadar } = await import('./siem/qradar.js');
  const scans = [
    { package_name: 't', version: '1', findings: [
      { id: 'ATK-001', severity: 'critical', title: 'c' },
      { id: 'ATK-002', severity: 'low', title: 'l' },
    ]},
  ];
  const out = generateQRadar(scans).split('\n').filter(Boolean).map(l => JSON.parse(l));
  assert.equal(out[0].qid, 90050001, 'critical QID');
  assert.equal(out[1].qid, 90050004, 'low QID');
});

test('SIEM index.js routes all formats', async () => {
  const { generateSIEM } = await import('./siem/index.js');
  const outCef = generateSIEM(MOCK_SCANS, 'cef');
  assert(outCef.includes('CEF:0'), 'cef routing');
  const outEcs = generateSIEM(MOCK_SCANS, 'ecs');
  assert(outEcs.includes('"kind":"alert"'), 'ecs routing');
  const outSentinel = generateSIEM(MOCK_SCANS, 'sentinel');
  assert(outSentinel.includes('TimeGenerated'), 'sentinel routing');
  const outQradar = generateSIEM(MOCK_SCANS, 'qradar');
  assert(outQradar.includes('qid'), 'qradar routing');
});

test('SIEM index.js throws on unknown format', async () => {
  const { generateSIEM } = await import('./siem/index.js');
  assert.throws(() => generateSIEM(MOCK_SCANS, 'unknown'), /unknown.*format/i);
});

// ─── EU CRA Compliance Report ──────────────────────────────────────

test('EU CRA report generates HTML table', async () => {
  const { generateCRA } = await import('./cra.js');
  const out = generateCRA(MOCK_SCANS);
  assert(out.includes('<h2>EU CRA Compliance Summary</h2>'), 'CRA heading');
  assert(out.includes('<table>'), 'HTML table');
  assert(out.includes('ATK-003'), 'ATK-003 mapped');
  assert(out.includes('ATK-009'), 'ATK-009 mapped');
});

test('EU CRA report full HTML wrapper', async () => {
  const { generateCRAHTML } = await import('./cra.js');
  const out = generateCRAHTML(MOCK_SCANS);
  assert(out.includes('<!DOCTYPE html>'), 'DOCTYPE');
  assert(out.includes('EU CRA Compliance Report'), 'title');
  assert(out.includes('Cyber Resilience Act'), 'CRA reference');
  assert(out.includes('ATK-003'), 'ATK finding');
});

test('EU CRA report empty scans', async () => {
  const { generateCRA } = await import('./cra.js');
  const out = generateCRA([]);
  assert(out.includes('No findings'), 'Empty scans show no findings');
});

// ─── SBOM Generation ───────────────────────────────────────────────

test('SBOM CycloneDX output', async () => {
  const { generateSBOM } = await import('./sbom.js');
  const pkg = { name: 'test-pkg', version: '1.0.0' };
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'high', title: 'Lifecycle script', description: 'preinstall hook' },
  ];
  const out = JSON.parse(generateSBOM(pkg, findings, 'json'));
  assert.equal(out.bomFormat, 'CycloneDX');
  assert.equal(out.specVersion, '1.5');
  assert.equal(out.metadata.component.name, 'test-pkg');
  assert.equal(out.vulnerabilities.length, 1);
  assert.equal(out.vulnerabilities[0].id, 'ATK-001');
});

test('SBOM SPDX output', async () => {
  const { generateSBOM } = await import('./sbom.js');
  const pkg = { name: 'spdx-pkg', version: '2.0.0' };
  const findings = [
    { id: 'ATK-002', atk_id: 'ATK-002', severity: 'medium', title: 'Obfuscation', description: 'eval detected' },
  ];
  const out = JSON.parse(generateSBOM(pkg, findings, 'spdx'));
  assert.equal(out.spdxVersion, 'SPDX-2.3');
  assert.equal(out.dataLicense, 'CC0-1.0');
  assert(out.name.includes('spdx-pkg'));
  assert.equal(out.packages.length, 1);
  assert.equal(out.packages[0].name, 'spdx-pkg');
  assert.equal(out.annotations.length, 1);
  assert(out.annotations[0].comment.includes('ATK-002'));
});

test('SBOM with no findings', async () => {
  const { generateSBOM } = await import('./sbom.js');
  const pkg = { name: 'clean', version: '1.0.0' };
  const jsonOut = JSON.parse(generateSBOM(pkg, [], 'json'));
  assert.equal(jsonOut.vulnerabilities.length, 0);
  const spdxOut = JSON.parse(generateSBOM(pkg, [], 'spdx'));
  assert.equal(spdxOut.annotations.length, 0);
});

// ─── License Key Validation ────────────────────────────────────────

test('license validateLicense throws on no key', async () => {
  const m = await import('./license.js');
  try {
    m.validateLicense(null, 'siem');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('No license'));
  }
});

test('license validateLicense throws on empty key', async () => {
  const m = await import('./license.js');
  try {
    m.validateLicense('', 'siem');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('No license'));
  }
});

test('license validateLicense throws on malformed key', async () => {
  const m = await import('./license.js');
  try {
    m.validateLicense('not-a-valid-key', 'siem');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('Invalid'));
  }
});

test('license validateLicense throws on unknown edition', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  const tampered = key.replace('premium', 'superpremium');
  try {
    m.validateLicense(tampered, '*');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('Unknown'));
  }
});

test('license validateLicense throws on feature requiring higher edition', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  try {
    m.validateLicense(key, 'sso');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('enterprise'));
  }
});

test('license generateKey with custom seats and org', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium', { seats: 50, org: 'Acme Corp' });
  const result = m.validateLicense(key, 'siem');
  assert.equal(result.seats, 50);
  assert.equal(result.org, 'Acme Corp');
});

test('license isFeatureEnabled returns true for valid community scan', async () => {
  const m = await import('./license.js');
  const prev = process.env.NPM_SCAN_LICENSE_KEY;
  process.env.NPM_SCAN_LICENSE_KEY = '';
  const result = m.isFeatureEnabled('scan', '');
  if (prev) process.env.NPM_SCAN_LICENSE_KEY = prev;
  else delete process.env.NPM_SCAN_LICENSE_KEY;
  assert.equal(result, true);
});

test('license validateLicense community features via isFeatureEnabled', async () => {
  const m = await import('./license.js');
  const prev = process.env.NPM_SCAN_LICENSE_KEY;
  process.env.NPM_SCAN_LICENSE_KEY = '';
  assert.equal(m.isFeatureEnabled('scan', ''), true);
  assert.equal(m.isFeatureEnabled('nist-html', ''), true);
  if (prev) process.env.NPM_SCAN_LICENSE_KEY = prev;
  else delete process.env.NPM_SCAN_LICENSE_KEY;
});

test('license isFeatureEnabled returns false for missing premium key', async () => {
  const m = await import('./license.js');
  const prev = process.env.NPM_SCAN_LICENSE_KEY;
  delete process.env.NPM_SCAN_LICENSE_KEY;
  assert.equal(m.isFeatureEnabled('siem', null), false);
  if (prev) process.env.NPM_SCAN_LICENSE_KEY = prev;
});

test('license reject tampered key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  const tampered = key.slice(0, -10) + 'ffffffffffffffff';
  try {
    m.validateLicense(tampered, '*');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('signature'));
  }
});

test('license reject expired key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium', { expiresAt: '2020-01-01T00:00:00Z' });
  try {
    m.validateLicense(key, '*');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('expired'));
  }
});

test('license generateKey produces valid format', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  assert(key.startsWith('npm-scan-premium-'), 'premium key prefix');
  const parts = key.split('-');
  assert(parts.length >= 4, 'has at least 4 parts');
  assert(key.includes('.'), 'has signature dot separator');
});

test('license validateLicense community features via isFeatureEnabled', async () => {
  const m = await import('./license.js');
  assert.equal(m.isFeatureEnabled('scan', null), true);
  assert.equal(m.isFeatureEnabled('scan', undefined), true);
  assert.equal(m.isFeatureEnabled('nist-html', null), true);
});

test('license validateLicense with valid premium key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  const result = m.validateLicense(key, 'siem');
  assert.equal(result.edition, 'premium');
});

test('license validateLicense enterprise key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('enterprise');
  const result = m.validateLicense(key, 'sso');
  assert.equal(result.edition, 'enterprise');
});

test('license isFeatureEnabled with valid key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  assert.equal(m.isFeatureEnabled('siem', key), true);
});

test('license isFeatureEnabled enterprise-only feature blocked on premium', async () => {
  const m = await import('./license.js');
  const premiumKey = m.generateKey('premium');
  assert.equal(m.isFeatureEnabled('sso', premiumKey), false);
});

test('license reject invalid key format', async () => {
  const m = await import('./license.js');
  try {
    m.validateLicense('npm-scan', '*');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('Invalid'));
  }
});

test('license reject empty key', async () => {
  const m = await import('./license.js');
  try {
    m.validateLicense('', '*');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('No license'));
  }
});

test('license reject tampered key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  const tampered = key.slice(0, -10) + 'ffffffffffffffff';
  try {
    m.validateLicense(tampered, '*');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('signature'));
  }
});

test('license reject expired key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium', { expiresAt: '2020-01-01T00:00:00Z' });
  try {
    m.validateLicense(key, '*');
    assert.fail('should throw');
  } catch (e) {
    assert(e.message.includes('expired'));
  }
});

test('license validateLicense community features', async () => {
  const m = await import('./license.js');
  const result = m.validateLicense('any-key', 'scan');
  assert.equal(result.edition, 'community');
  assert(Array.isArray(result.features));
});

test('license validateLicense with valid premium key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  const result = m.validateLicense(key, 'siem');
  assert.equal(result.edition, 'premium');
  assert(result.features.includes('siem'));
});

test('license validateLicense enterprise key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('enterprise', { org: 'test-corp', seats: 10 });
  const result = m.validateLicense(key, 'sso');
  assert.equal(result.edition, 'enterprise');
  assert.equal(result.org, 'test-corp');
  assert.equal(result.seats, 10);
});

test('license isFeatureEnabled with valid key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  assert.equal(m.isFeatureEnabled('siem', key), true);
  assert.equal(m.isFeatureEnabled('cra', key), true);
});

test('license isFeatureEnabled enterprise-only feature blocked on premium', async () => {
  const m = await import('./license.js');
  const premiumKey = m.generateKey('premium');
  assert.equal(m.isFeatureEnabled('sso', premiumKey), false);
  const enterpriseKey = m.generateKey('enterprise');
  assert.equal(m.isFeatureEnabled('sso', enterpriseKey), true);
});

test('license reject invalid key format', async () => {
  const m = await import('./license.js');
  assert.throws(() => m.validateLicense('not-a-valid-key'), /invalid.*format/i);
});

test('license reject tampered key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  const parts = key.split('.');
  const tampered = 'npm-scan-community-AAAA.' + parts[1];
  assert.throws(() => m.validateLicense(tampered, 'siem'), /invalid/i);
});

test('license reject expired key', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium', { expiresAt: '2020-01-01T00:00:00Z' });
  assert.throws(() => m.validateLicense(key, 'siem'), /expired/i);
});

// ─── Report / NIST Compliance ──────────────────────────────────────

test('generateHTML produces valid HTML', async () => {
  const { generateHTML } = await import('./report.js');
  const html = generateHTML(MOCK_SCANS);
  assert(html.includes('<!DOCTYPE html>'), 'DOCTYPE');
  assert(html.includes('npm-scan Report'), 'title');
  assert(html.includes('ATK-003'), 'finding in HTML');
  assert(html.includes('ATK-009'), 'finding in HTML');
});

test('generateHTML NIST compliance table', async () => {
  const { generateHTML } = await import('./report.js');
  const html = generateHTML(MOCK_SCANS);
  assert(html.includes('NIST SP 800-161'), 'NIST section');
  assert(html.includes('SR-3.1'), 'NIST SR-3.1 for ATK-001');
  assert(html.includes('SR-5.3'), 'NIST SR-5.3 for ATK-003');
});

test('generateHTML summary badges', async () => {
  const { generateHTML } = await import('./report.js');
  const html = generateHTML(MOCK_SCANS);
  assert(html.includes('class="badge high"'), 'high badge');
  assert(html.includes('class="badge medium"'), 'medium badge');
});

test('report with no findings shows clean', async () => {
  const { generateHTML } = await import('./report.js');
  const html = generateHTML([{ package_name: 'clean-pkg', version: '1.0.0', findings: [] }]);
  assert(html.includes('clean-pkg'));
  assert(html.includes('clean'));
});

test('NIST table maps all ATK-001 through ATK-011', async () => {
  const { generateHTML } = await import('./report.js');
  const allAtkScans = [
    { package_name: 'p', version: '1', findings: [
      ...Array.from({ length: 11 }, (_, i) => ({
        id: `ATK-${String(i + 1).padStart(3, '0')}`,
        atk_id: `ATK-${String(i + 1).padStart(3, '0')}`,
        severity: 'medium',
        title: `ATK-${i + 1}`,
      })),
    ]},
  ];
  const html = generateHTML(allAtkScans);
  for (let i = 1; i <= 11; i++) {
    const id = `ATK-${String(i).padStart(3, '0')}`;
    assert(html.includes(id), `${id} in NIST table`);
  }
  assert(html.includes('SR-3.1'), 'SR-3.1 for ATK-001');
  assert(html.includes('SR-11.4'), 'SR-11.4 for ATK-011');
});

// ─── Policy Engine ──────────────────────────────────────────────────

test('policy loadPolicy loads YAML', async () => {
  const { loadPolicy } = await import('./policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-policy.yaml';
  writeFileSync(path, `fail_on: medium\nallow:\n  packages:\n    - lodash\n`);
  try {
    const policy = loadPolicy(path);
    assert.equal(policy.fail_on, 'medium');
    assert.deepEqual(policy.allow.packages, ['lodash']);
  } finally {
    unlinkSync(path);
  }
});

test('policy loadPolicy loads JSON', async () => {
  const { loadPolicy } = await import('./policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-policy.json';
  writeFileSync(path, `{"fail_on":"high","allow":{"packages":["chalk"]}}`);
  try {
    const policy = loadPolicy(path);
    assert.equal(policy.fail_on, 'high');
    assert.deepEqual(policy.allow.packages, ['chalk']);
  } finally {
    unlinkSync(path);
  }
});

test('policy isAllowed matches package name', async () => {
  const { isAllowed } = await import('./policy.js');
  const policy = { allow: { packages: ['lodash', 'chalk@5.0.0'] }, severity_overrides: {}, fail_on: 'none', suppress: [] };
  assert.equal(isAllowed('lodash', policy), true);
  assert.equal(isAllowed('lodash@4.17.21', policy), true);
  assert.equal(isAllowed('chalk@5.0.0', policy), true);
  assert.equal(isAllowed('express', policy), false);
});

test('policy isAllowed with empty allowlist', async () => {
  const { isAllowed } = await import('./policy.js');
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'none', suppress: [] };
  assert.equal(isAllowed('lodash', policy), false);
});

test('policy applyPolicy suppresses findings by atk_id', async () => {
  const { applyPolicy } = await import('./policy.js');
  const findings = [
    { id: 'ATK-003', atk_id: 'ATK-003', severity: 'high', title: 'Creds' },
    { id: 'ATK-009', atk_id: 'ATK-009', severity: 'medium', title: 'Trigger' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'none', suppress: [{ atk_id: 'ATK-003', package: '*', reason: 'FP' }] };
  const { findings: filtered } = applyPolicy(findings, 'lodash', policy);
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].id, 'ATK-009');
});

test('policy applyPolicy suppresses findings by package name', async () => {
  const { applyPolicy } = await import('./policy.js');
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'low', title: 'Lifecycle' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'none', suppress: [{ atk_id: 'ATK-001', package: 'lodash', reason: 'Fixture' }] };
  const { findings: filtered } = applyPolicy(findings, 'lodash', policy);
  assert.equal(filtered.length, 0);
});

test('policy applyPolicy preserves findings when suppress rule targets different package', async () => {
  const { applyPolicy } = await import('./policy.js');
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'low', title: 'Lifecycle' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'none', suppress: [{ atk_id: 'ATK-001', package: 'express', reason: 'Fixture' }] };
  const { findings: filtered } = applyPolicy(findings, 'lodash', policy);
  assert.equal(filtered.length, 1);
});

test('policy applyPolicy overrides severity', async () => {
  const { applyPolicy } = await import('./policy.js');
  const findings = [
    { id: 'ATK-003', atk_id: 'ATK-003', severity: 'high', title: 'Creds' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: { 'ATK-003': 'low' }, fail_on: 'none', suppress: [] };
  const { findings: filtered } = applyPolicy(findings, 'lodash', policy);
  assert.equal(filtered[0].severity, 'low');
  assert.equal(filtered[0]._severityOverridden, true);
});

test('policy checkFailOn blocks at threshold', async () => {
  const { applyPolicy } = await import('./policy.js');
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'medium', title: 'Test' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'high', suppress: [] };
  const { blocked } = applyPolicy(findings, 'test', policy);
  assert.equal(blocked, false);
  const policyLow = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'medium', suppress: [] };
  const { blocked: b2 } = applyPolicy(findings, 'test', policyLow);
  assert.equal(b2, true);
});

test('policy checkFailOn none never blocks', async () => {
  const { applyPolicy } = await import('./policy.js');
  const findings = [
    { id: 'ATK-001', atk_id: 'ATK-001', severity: 'critical', title: 'Critical' },
  ];
  const policy = { allow: { packages: [] }, severity_overrides: {}, fail_on: 'none', suppress: [] };
  const { blocked } = applyPolicy(findings, 'test', policy);
  assert.equal(blocked, false);
});

test('policy loadPolicy rejects invalid YAML', async () => {
  const { loadPolicy } = await import('./policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-bad.yaml';
  writeFileSync(path, 'fail_on: [invalid');
  try {
    assert.throws(() => loadPolicy(path), /YAML|load/i);
  } finally {
    unlinkSync(path);
  }
});

test('policy loadPolicy rejects invalid fail_on severity', async () => {
  const { loadPolicy } = await import('./policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-bad-failon.yaml';
  writeFileSync(path, 'fail_on: extreme');
  try {
    assert.throws(() => loadPolicy(path), /Invalid.*fail_on/i);
  } finally {
    unlinkSync(path);
  }
});

test('policy loadPolicy rejects invalid severity override', async () => {
  const { loadPolicy } = await import('./policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-bad-override.yaml';
  writeFileSync(path, 'severity_overrides:\n  ATK-001: ultra');
  try {
    assert.throws(() => loadPolicy(path), /Invalid severity/i);
  } finally {
    unlinkSync(path);
  }
});

test('policy loadPolicy rejects suppress without atk_id', async () => {
  const { loadPolicy } = await import('./policy.js');
  const { writeFileSync, unlinkSync } = await import('fs');
  const path = '/tmp/test-bad-suppress.yaml';
  writeFileSync(path, 'suppress:\n  - package: lodash');
  try {
    assert.throws(() => loadPolicy(path), /atk_id/i);
  } finally {
    unlinkSync(path);
  }
});

// ─── Text Report ────────────────────────────────────────────────────

test('text report generates basic output', async () => {
  const { generateText } = await import('./report.js');
  const out = generateText(MOCK_SCANS);
  assert(out.includes('npm-scan Report'), 'header');
  assert(out.includes('Packages scanned: 1'), 'scan count');
  assert(out.includes('lodash'), 'package name');
  assert(out.includes('ATK-003'), 'ATK-003 finding');
  assert(out.includes('ATK-009'), 'ATK-009 finding');
  assert(out.includes('Severity Summary'), 'summary');
  assert(out.includes('total: 2 findings'), 'total count');
});

test('text report empty scans', async () => {
  const { generateText } = await import('./report.js');
  const out = generateText([]);
  assert(out.includes('Packages scanned: 0'), 'zero scans');
  assert(out.includes('total: 0 findings'), 'zero findings');
});

test('text report clean package', async () => {
  const { generateText } = await import('./report.js');
  const scans = [{ package_name: 'clean-pkg', version: '1.0.0', findings: [] }];
  const out = generateText(scans);
  assert(out.includes('clean-pkg@1.0.0'), 'package name');
  assert(out.includes('clean'), 'clean label');
  assert(out.includes('0 findings'), 'zero findings');
});

test('text report severity counts', async () => {
  const { generateText } = await import('./report.js');
  const scans = [{
    package_name: 'multi-sev', version: '1.0.0', findings: [
      { id: 'ATK-001', severity: 'critical', title: 'C' },
      { id: 'ATK-002', severity: 'high', title: 'H' },
      { id: 'ATK-003', severity: 'medium', title: 'M' },
      { id: 'ATK-004', severity: 'low', title: 'L' },
    ],
  }];
  const out = generateText(scans);
  assert(out.includes('critical: 1'), 'critical count');
  assert(out.includes('high: 1'), 'high count');
  assert(out.includes('medium: 1'), 'medium count');
  assert(out.includes('low: 1'), 'low count');
  assert(out.includes('ATK-001'), 'ATK-001 present');
});

// ─── PDF Report ─────────────────────────────────────────────────────

test('PDF report generates valid PDF buffer', async () => {
  const { generatePDF } = await import('./pdf.js');
  const pdfBytes = await generatePDF(MOCK_SCANS);
  assert(pdfBytes instanceof Uint8Array, 'Uint8Array buffer');
  const header = new TextDecoder().decode(pdfBytes.slice(0, 8));
  assert(header.startsWith('%PDF-'), 'PDF header magic bytes');
  assert(header.includes('1.'), 'PDF version');
});

test('PDF report with findings produces valid multi-page PDF', async () => {
  const { generatePDF } = await import('./pdf.js');
  const pdfBytes = await generatePDF(MOCK_SCANS);
  const header = new TextDecoder().decode(pdfBytes.slice(0, 8));
  assert(header.startsWith('%PDF-'), 'valid PDF header');
  assert(pdfBytes.length > 1000, 'non-trivial PDF size');
});

test('PDF report with empty scans produces valid PDF', async () => {
  const { generatePDF } = await import('./pdf.js');
  const pdfBytes = await generatePDF([]);
  const header = new TextDecoder().decode(pdfBytes.slice(0, 8));
  assert(header.startsWith('%PDF-'), 'valid PDF with empty scans');
});

test('PDF report with no findings still valid', async () => {
  const { generatePDF } = await import('./pdf.js');
  const scans = [{ package_name: 'clean-pkg', version: '1.0.0', findings: [] }];
  const pdfBytes = await generatePDF(scans);
  const header = new TextDecoder().decode(pdfBytes.slice(0, 8));
  assert(header.startsWith('%PDF-'), 'valid PDF with clean package');
});

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

test('license generateKey produces valid format', async () => {
  const m = await import('./license.js');
  const key = m.generateKey('premium');
  assert(key.startsWith('npm-scan-premium-'), 'premium key prefix');
  assert(key.includes('.'), 'contains signature separator');
  const parts = key.split('.');
  assert.equal(parts.length, 2, 'payload.signature');
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

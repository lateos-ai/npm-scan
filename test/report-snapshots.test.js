import { test } from 'node:test';
import assert from 'assert/strict';
import { MOCK_SCANS, EMPTY_SCAN, MULTI_SEV_SCAN, ALL_ATK_SCAN } from './fixtures/mock-data.js';

test('report: HTML contains DOCTYPE and title', async () => {
  const { generateHTML } = await import('../backend/report.js');
  const html = generateHTML(MOCK_SCANS);
  assert(html.includes('<!DOCTYPE html>'));
  assert(html.includes('npm-scan Report'));
});

test('report: HTML shows finding details', async () => {
  const { generateHTML } = await import('../backend/report.js');
  const html = generateHTML(MOCK_SCANS);
  assert(html.includes('ATK-003'));
  assert(html.includes('ATK-009'));
  assert(html.includes('lodash'));
});

test('report: HTML contains severity badges', async () => {
  const { generateHTML } = await import('../backend/report.js');
  const html = generateHTML(MOCK_SCANS);
  assert(html.includes('class="badge high"'));
  assert(html.includes('class="badge medium"'));
});

test('report: HTML empty scans shows clean', async () => {
  const { generateHTML } = await import('../backend/report.js');
  const html = generateHTML([EMPTY_SCAN]);
  assert(html.includes('clean'));
  assert(html.includes('clean-pkg'));
});

test('report: HTML NIST table maps all 11 ATK IDs', async () => {
  const { generateHTML } = await import('../backend/report.js');
  const html = generateHTML([ALL_ATK_SCAN]);
  for (let i = 1; i <= 11; i++) {
    const id = `ATK-${String(i).padStart(3, '0')}`;
    assert(html.includes(id), `${id} missing from NIST table`);
  }
  assert(html.includes('SR-3.1'));
  assert(html.includes('SR-11.4'));
});

test('report: HTML NIST section heading present', async () => {
  const { generateHTML } = await import('../backend/report.js');
  const html = generateHTML(MOCK_SCANS);
  assert(html.includes('NIST SP 800-161'));
  assert(html.includes('SR-3.1'));
  assert(html.includes('SR-5.3'));
});

test('report: text basic output includes header and findings', async () => {
  const { generateText } = await import('../backend/report.js');
  const out = generateText(MOCK_SCANS);
  assert(out.includes('npm-scan Report'));
  assert(out.includes('Packages scanned: 1'));
  assert(out.includes('lodash'));
  assert(out.includes('ATK-003'));
  assert(out.includes('total: 2 findings'));
});

test('report: text empty scans shows zero counts', async () => {
  const { generateText } = await import('../backend/report.js');
  const out = generateText([]);
  assert(out.includes('Packages scanned: 0'));
  assert(out.includes('total: 0 findings'));
});

test('report: text clean package shows clean label', async () => {
  const { generateText } = await import('../backend/report.js');
  const out = generateText([EMPTY_SCAN]);
  assert(out.includes('clean-pkg@1.0.0'));
  assert(out.includes('clean'));
  assert(out.includes('0 findings'));
});

test('report: text severity counts are correct', async () => {
  const { generateText } = await import('../backend/report.js');
  const out = generateText([MULTI_SEV_SCAN]);
  assert(out.includes('critical: 1'));
  assert(out.includes('high: 1'));
  assert(out.includes('medium: 1'));
  assert(out.includes('low: 1'));
  assert(out.includes('total: 4 findings'));
});

test('report: text Severity Summary section present', async () => {
  const { generateText } = await import('../backend/report.js');
  const out = generateText(MOCK_SCANS);
  assert(out.includes('Severity Summary'));
});

test('report: CRA generates HTML table', async () => {
  const { generateCRA } = await import('../backend/cra.js');
  const out = generateCRA(MOCK_SCANS);
  assert(out.includes('<h2>EU CRA Compliance Summary</h2>'));
  assert(out.includes('<table>'));
  assert(out.includes('ATK-003'));
});

test('report: CRA full HTML wrapper', async () => {
  const { generateCRAHTML } = await import('../backend/cra.js');
  const out = generateCRAHTML(MOCK_SCANS);
  assert(out.includes('<!DOCTYPE html>'));
  assert(out.includes('EU CRA Compliance Report'));
  assert(out.includes('Cyber Resilience Act'));
});

test('report: CRA empty scans shows no findings', async () => {
  const { generateCRA } = await import('../backend/cra.js');
  const out = generateCRA([]);
  assert(out.includes('No findings'));
});

test('report: PDF for empty scans is valid', async () => {
  const { generatePDF } = await import('../backend/pdf.js');
  const pdfBytes = await generatePDF([]);
  const header = new TextDecoder().decode(pdfBytes.slice(0, 8));
  assert(header.startsWith('%PDF-'));
});

test('report: PDF for populated scans is valid', async () => {
  const { generatePDF } = await import('../backend/pdf.js');
  const pdfBytes = await generatePDF(MOCK_SCANS);
  const header = new TextDecoder().decode(pdfBytes.slice(0, 8));
  assert(header.startsWith('%PDF-'));
  assert(pdfBytes.length > 1000);
});

import { test } from 'node:test';
import assert from 'assert/strict';
import {
  generateSARIF, generateCSV, generateSTIG, calculateRiskScore
} from '../backend/report.js';

test('report: generateSARIF with no findings', async () => {
  const scan = { package_name: 'test', version: '1.0.0', findings: [] };
  const sarif = JSON.parse(generateSARIF(scan));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 0);
});

test('report: generateCSV with empty scans', async () => {
  const csv = generateCSV([]);
  assert(csv.startsWith('id,severity'));
  assert.equal(csv, 'id,severity,title,description,evidence,package_name,version\n');
});

test('report: generateCSV with findings', async () => {
  const scans = [{
    package_name: 'test', version: '1.0.0',
    findings: [{ id: 'ATK-001', severity: 'high', title: 'pre', description: 'test, desc', evidence: '' }]
  }];
  const csv = generateCSV(scans);
  assert(csv.includes('ATK-001'));
  assert(!csv.includes('test, desc'));
});

test('report: generateCSV null scans handled', async () => {
  const csv = generateCSV(null);
  assert(csv.startsWith('id,severity'));
});

test('report: generateSTIG maps all 11 ATK IDs', async () => {
  const stig = generateSTIG([{
    package_name: 'test', version: '1.0.0', findings: []
  }]);
  assert(stig.includes('SRG-APP-000141'));
  assert(stig.includes('SRG-APP-000151'));
  assert(stig.includes('COMPLETE'));
});

test('report: generateSTIG with findings marks NOT APPLICABLE', async () => {
  const scans = [{
    package_name: 'test', version: '1.0.0',
    findings: [{ id: 'ATK-001', severity: 'high', title: 'preinstall' }]
  }];
  const stig = generateSTIG(scans);
  assert(stig.includes('NOT APPLICABLE'));
  assert(stig.includes('HIGH: preinstall'));
});

test('report: generateSTIG lists multiple findings', async () => {
  const scans = [{
    package_name: 'test', version: '1.0.0',
    findings: [
      { id: 'ATK-001', severity: 'high', title: 'preinstall' },
      { id: 'ATK-007', severity: 'high', title: 'typosquat' }
    ]
  }];
  const stig = generateSTIG(scans);
  assert(stig.includes('HIGH: preinstall'));
});

test('report: calculateRiskScore returns 0.0 for empty findings', async () => {
  const score = calculateRiskScore([]);
  assert.equal(score, '0.0');
});

test('report: calculateRiskScore computes correctly', async () => {
  const score = calculateRiskScore([{ severity: 'high' }, { severity: 'low' }], 1);
  assert.notEqual(score, '0.0');
});

test('report: calculateRiskScore caps at 10', async () => {
  const findings = [];
  for (let i = 0; i < 20; i++) findings.push({ severity: 'critical' });
  const score = calculateRiskScore(findings, 1);
  assert.equal(score, '10.0');
});

test('report: calculateRiskScore averages by totalPackages', async () => {
  const score = calculateRiskScore([{ severity: 'high' }], 10);
  assert.equal(score, '0.7');
});

test('report: generateSARIF maps all severity levels', async () => {
  const scan = {
    package_name: 'test', version: '1.0.0',
    findings: [
      { id: 'ATK-001', severity: 'critical', description: 'c', title: 'c' },
      { id: 'ATK-002', severity: 'high', description: 'h', title: 'h' },
      { id: 'ATK-003', severity: 'medium', description: 'm', title: 'm' },
      { id: 'ATK-004', severity: 'low', description: 'l', title: 'l' },
    ]
  };
  const sarif = JSON.parse(generateSARIF(scan));
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[1].level, 'error');
  assert.equal(sarif.runs[0].results[2].level, 'warning');
  assert.equal(sarif.runs[0].results[3].level, 'note');
});
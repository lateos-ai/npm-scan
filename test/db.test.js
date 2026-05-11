import { test } from 'node:test';
import assert from 'assert/strict';
import { existsSync } from 'fs';
import { join } from 'path';

test('db: saveScan stores and returns scan ID', async () => {
  const { saveScan, getScan, close } = await import('../backend/db.js');
  const id = await saveScan('test-pkg', '1.0.0', []);
  assert(typeof id === 'number' && id > 0, 'returns positive integer ID');
  const scan = await getScan(id);
  assert(scan, 'scan exists in DB');
  assert.equal(scan.package_name, 'test-pkg');
  assert.equal(scan.version, '1.0.0');
  await close();
});

test('db: saveScan with findings stores them', async () => {
  const { saveScan, getFindings, close } = await import('../backend/db.js');
  const findings = [
    { id: 'ATK-001', severity: 'high', title: 'Lifecycle', evidence: 'preinstall' },
    { id: 'ATK-002', severity: 'medium', title: 'Obfuscated', evidence: 'eval' },
  ];
  const id = await saveScan('multi-find', '1.0.0', findings);
  const stored = await getFindings(id);
  assert.equal(stored.length, 2);
  assert(stored.some(f => f.atk_id === 'ATK-001'));
  assert(stored.some(f => f.severity === 'medium'));
  await close();
});

test('db: saveScan empty findings returns zero findings', async () => {
  const { saveScan, getFindings, close } = await import('../backend/db.js');
  const id = await saveScan('clean-pkg', '1.0.0', []);
  const stored = await getFindings(id);
  assert.equal(stored.length, 0);
  await close();
});

test('db: getRecentScans returns scans in descending ID order', async () => {
  const { saveScan, getRecentScans, close } = await import('../backend/db.js');
  const id1 = await saveScan('first', '1.0.0', []);
  const id2 = await saveScan('second', '2.0.0', []);
  const recent = await getRecentScans(10);
  const ids = recent.map(s => s.id);
  assert(ids.includes(id1), `id1=${id1} should be in [${ids}]`);
  assert(ids.includes(id2), `id2=${id2} should be in [${ids}]`);
  await close();
});

test('db: getScan returns null for non-existent ID', async () => {
  const { getScan, close } = await import('../backend/db.js');
  const scan = await getScan(999999);
  assert.equal(scan, null);
  await close();
});

test('db: getFindings returns empty for non-existent scan', async () => {
  const { getFindings, close } = await import('../backend/db.js');
  const findings = await getFindings(999999);
  assert.deepEqual(findings, []);
  await close();
});

test('db: multiple scans each have independent findings', async () => {
  const { saveScan, getFindings, close } = await import('../backend/db.js');
  const id1 = await saveScan('pkg-a', '1.0.0', [{ id: 'ATK-001', severity: 'high', title: 'A' }]);
  const id2 = await saveScan('pkg-b', '1.0.0', [{ id: 'ATK-002', severity: 'low', title: 'B' }]);
  const f1 = await getFindings(id1);
  const f2 = await getFindings(id2);
  assert.equal(f1.length, 1);
  assert.equal(f1[0].atk_id, 'ATK-001');
  assert.equal(f2.length, 1);
  assert.equal(f2[0].atk_id, 'ATK-002');
  await close();
});

test('db: persist writes to disk (npm-scan.db exists)', async () => {
  const { saveScan, close } = await import('../backend/db.js');
  await saveScan('persist-test', '1.0.0', []);
  await close();
  assert(existsSync(join(process.cwd(), 'npm-scan.db')), 'DB file written');
});

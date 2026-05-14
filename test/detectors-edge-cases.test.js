import { test } from 'node:test';
import assert from 'assert/strict';
import * as detectors from '../backend/detectors/index.js';

test('detectors: empty package with no files produces zero findings', async () => {
  const findings = await detectors.runAll({});
  assert.equal(findings.length, 0);
});

test('detectors: empty scripts produce zero ATK-001 findings', async () => {
  const pkg = { scripts: { test: 'mocha' }, name: 'test' };
  const findings = await detectors.runAll(pkg);
  assert(!findings.some(f => f.id === 'ATK-001'));
});

test('detectors: ATK-001 scripts without dangerous commands are clean', async () => {
  const pkg = { scripts: { preinstall: 'mkdir build && npm run build' } };
  const findings = await detectors.runAll(pkg);
  assert(!findings.some(f => f.id === 'ATK-001'));
});

test('detectors: ATK-001 postversion with benign content still caught by "sh" regex', async () => {
  const pkg = { scripts: { postversion: 'git push --tags' } };
  const findings = await detectors.runAll(pkg);
  assert(findings.some(f => f.id === 'ATK-001'));
});

test('detectors: ATK-002 clean code with eval but no decode produces no finding', async () => {
  const files = [{ path: 'i.js', content: 'const x = eval("1+1")' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-002'));
});

test('detectors: ATK-002 clean Buffer.from for data formatting produces no finding', async () => {
  const files = [{ path: 'i.js', content: 'const buf = Buffer.from("hello world", "utf8")' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-002'));
});

test('detectors: ATK-002 new Function without decode not flagged', async () => {
  const files = [{ path: 'i.js', content: 'const f = new Function("a", "b", "return a + b")' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-002'));
});

test('detectors: ATK-002 hex decode with eval flagged', async () => {
  const files = [{ path: 'i.js', content: 'eval(Buffer.from("636f6e736f6c652e6c6f67282268656c6c6f2229", "hex"))' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-002'));
});

test('detectors: ATK-002 charcode with eval flagged', async () => {
  const files = [{ path: 'i.js', content: 'eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103))' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-002'));
});

test('detectors: ATK-003 no cred patterns is clean', async () => {
  const files = [{ path: 'i.js', content: 'console.log(process.env.NODE_ENV)' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-003'));
});

test('detectors: ATK-003 .npmrc access flagged', async () => {
  const files = [{ path: 'i.js', content: 'fs.readFileSync(".npmrc")' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-003'));
});

test('detectors: ATK-004 no persistence dirs is clean', async () => {
  const files = [{ path: 'i.js', content: 'fs.mkdirSync("dist")' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-004'));
});

test('detectors: ATK-005 clean network calls are not flagged', async () => {
  const files = [{ path: 'i.js', content: 'fetch("https://registry.npmjs.org/lodash")' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-005'));
});

test('detectors: ATK-006 clean dependency names produce no finding', async () => {
  const pkg = { dependencies: { express: '4.0.0', lodash: '4.0.0' } };
  const findings = await detectors.runAll(pkg);
  assert(!findings.some(f => f.id === 'ATK-006'));
});

test('detectors: ATK-007 no typosquat in clean deps', async () => {
  const pkg = { dependencies: { express: '4.0.0', lodash: '4.17.21' } };
  const findings = await detectors.runAll(pkg);
  assert(!findings.some(f => f.id === 'ATK-007'));
});

test('detectors: ATK-007 short names (<4 chars) ignored', async () => {
  const pkg = { dependencies: { ax: '1.0.0', rx: '2.0.0' } };
  const findings = await detectors.runAll(pkg);
  assert(!findings.some(f => f.id === 'ATK-007'));
});

test('detectors: ATK-008 matching repo produces no finding', async () => {
  const pkg = { name: 'lodash', repository: { url: 'https://github.com/lodash/lodash.git' } };
  const findings = await detectors.runAll(pkg);
  assert(!findings.some(f => f.id === 'ATK-008'));
});

test('detectors: ATK-008 no repo info is clean', async () => {
  const pkg = { name: 'some-pkg' };
  const findings = await detectors.runAll(pkg);
  assert(!findings.some(f => f.id === 'ATK-008'));
});

test('detectors: ATK-009 no CI checks or time triggers is clean', async () => {
  const files = [{ path: 'i.js', content: 'const x = Date.now()' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-009'));
});

test('detectors: ATK-009 Date.now() without suspicious context is clean', async () => {
  const files = [{ path: 'i.js', content: 'const start = Date.now(); doWork(); const end = Date.now()' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-009'));
});

test('detectors: ATK-010 no evasion patterns is clean', async () => {
  const files = [{ path: 'i.js', content: 'console.log(os.hostname())' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-010'));
});

test('detectors: ATK-010 single fingerprinting API is clean', async () => {
  const files = [{ path: 'i.js', content: 'const pid = process.pid' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-010'));
});

test('detectors: ATK-011 no propagation patterns is clean', async () => {
  const files = [{ path: 'i.js', content: 'exec("npm test")' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-011'));
});

test('detectors: ATK-011 self-name aware triggers medium finding', async () => {
  const files = [{ path: 'i.js', content: 'const name = process.env.npm_package_name' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-011'));
  assert.equal(findings.find(f => f.id === 'ATK-011').severity, 'medium');
});

test('detectors: ATK-010 multi fingerprinting APIs triggers medium', async () => {
  const files = [{ path: 'i.js', content: 'const pid = process.pid; const ppid = process.ppid; const hn = os.hostname()' }];
  const findings = await detectors.runAll({}, files);
  const atk10 = findings.filter(f => f.id === 'ATK-010');
  assert(atk10.length > 0);
  assert.equal(atk10[0].severity, 'medium');
});

test('detectors: ATK-010 stack trace with code execution triggers medium', async () => {
  const files = [{ path: 'i.js', content: 'const e = new Error().stack; require("child_process").execSync("ls")' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-010'));
});

test('detectors: ATK-010 only Error().stack without exec does not trigger', async () => {
  const files = [{ path: 'i.js', content: 'const e = Error().stack; console.log(e)' }];
  const findings = await detectors.runAll({}, files);
  assert(!findings.some(f => f.id === 'ATK-010'));
});

test('detectors: ATK-010 debugger statement flagged', async () => {
  const files = [{ path: 'i.js', content: 'debugger; //debugger' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-010'));
  assert.equal(findings.find(f => f.id === 'ATK-010').severity, 'high');
});

test('detectors: ATK-010 detect analysis keywords flagged', async () => {
  const files = [{ path: 'i.js', content: 'if (detect("sandbox")) process.exit(0)' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-010'));
});

test('detectors: ATK-010 e.stack sandbox probe flagged', async () => {
  const files = [{ path: 'i.js', content: 'const s = e.stack; if (s.includes("sandbox")) console.log("detected")' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-010'));
});

test('detectors: ATK-010 --inspect flag detection flagged', async () => {
  const files = [{ path: 'i.js', content: 'if (process.argv.includes("--inspect")) {}' }];
  const findings = await detectors.runAll({}, files);
  assert(findings.some(f => f.id === 'ATK-010'));
});

test('detectors: known clean packages produce no high/critical findings', async () => {
  const cleanPkgs = [
    { scripts: { test: 'jest' }, dependencies: { express: '4.0.0' }, name: 'test' },
    { scripts: { build: 'tsc' }, dependencies: { lodash: '4.0.0' }, name: 'build-pkg' },
    { scripts: { start: 'node server.js' }, name: 'server-pkg' },
  ];
  for (const pkg of cleanPkgs) {
    const files = [{ path: 'index.js', content: 'module.exports = 42' }];
    const findings = await detectors.runAll(pkg, files);
    const highCrit = findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    assert.equal(highCrit.length, 0, `${pkg.name}: unexpected high/crit finding`);
  }
});

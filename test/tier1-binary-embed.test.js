import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-binary-embed.js';

const pad = (s) => s + '\0'.repeat(64);
const ELF = pad('\x7fELF');
const MACHO = pad(String.fromCharCode(0xfe, 0xed, 0xfa, 0xce));
const PE = pad('MZ');
const f = (path, content) => ({ path, content });

test('D4: extensionless cross-platform set in a <dir>/<os>-<arch>/<name> layout is detected', async () => {
  const bins = [
    f('.sckit/linux-amd64/sckit', ELF),
    f('.sckit/darwin-arm64/sckit', MACHO),
    f('.sckit/windows-amd64/sckit.exe', PE),
  ];
  const launcher = f(
    'index.js',
    "const { spawn } = require('child_process'); spawn(process.env.HOME + '/.sckit/linux-amd64/sckit', ['stage0'], { detached: true });"
  );
  const findings = await scan({ name: 'memos-plugin', version: '0.1.25' }, [launcher], null, [
    ...bins,
    launcher,
  ]);
  assert.ok(findings.length >= 1);
  const elfFinding = findings.find((x) => x.subtype === 'cross_platform_elf');
  assert.ok(elfFinding, 'expected a cross_platform_elf subtype');
  assert.equal(elfFinding.severity, 'critical');
  assert.ok(
    elfFinding.evidence.some((e) => e.startsWith('cross-platform binary set')),
    'expected cross-platform set evidence'
  );
});

test('D4: a single undeclared ELF binary is flagged', async () => {
  const bins = [f('payload', ELF)];
  const findings = await scan({ name: 'odd-pkg', version: '1.0.0' }, [], null, bins);
  assert.ok(findings.some((x) => x.subtype === 'elf_embedded'));
});

test('D4: electron is exempt', async () => {
  const findings = await scan({ name: 'electron', version: '30.0.0' }, [], null, [f('a', ELF)]);
  assert.deepEqual(findings, []);
});

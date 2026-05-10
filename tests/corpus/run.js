import assert from 'assert/strict';
import { globSync } from 'glob';
import { readFileSync, mkdtempSync } from 'fs';
import { execSync } from 'child_process';
import { fetchPackage, cleanup } from '../../backend/fetch.js';
import { runAll } from '../../backend/detectors/index.js';
import os from 'os';
import path from 'path';

function scanLocalTarball(tarPath) {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'npm-scan-corpus-'));
  execSync(`tar xzf "${tarPath}" -C "${tmpDir}"`, { stdio: 'pipe' });
  const pkgPath = globSync(path.join(tmpDir, '**', 'package.json'), { nodir: true })[0];
  if (!pkgPath) throw new Error(`No package.json in ${tarPath}`);
  const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
  const pkgDir = path.dirname(pkgPath);
  const jsFiles = globSync(path.join(pkgDir, '**', '*.js'), { nodir: true }).map(p => ({
    path: p,
    content: readFileSync(p, 'utf8')
  }));
  return { pkgJson, jsFiles, tmpDir };
}

let cleanFails = 0;
let malFails = 0;

console.log('--- Clean corpus (remote) ---');
for (const pkg of ['lodash', 'chalk', 'react', 'axios', 'express']) {
  try {
    const { pkgJson, jsFiles, tmpDir } = await fetchPackage(pkg);
    const findings = await runAll(pkgJson, jsFiles);
    const bad = findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    if (bad.length > 0) {
      console.log(`  FAIL ${pkg}: ${bad.length} high/crit (${bad.map(f => f.id).join(', ')})`);
      cleanFails++;
    } else {
      console.log(`  OK   ${pkg}`);
    }
    cleanup(tmpDir);
  } catch (e) {
    console.log(`  ERR  ${pkg}: ${e.message}`);
    cleanFails++;
  }
}

console.log('--- Malicious corpus (local) ---');
const malTars = globSync('tests/corpus/malicious/*.tgz');
for (const tar of malTars) {
  const name = path.basename(tar, '.tgz');
  try {
    const { pkgJson, jsFiles } = scanLocalTarball(tar);
    const findings = await runAll(pkgJson, jsFiles);
    if (findings.length === 0) {
      console.log(`  FAIL ${name}: no findings`);
      console.log(`    scripts: ${JSON.stringify(pkgJson.scripts || {})}`);
      console.log(`    deps: ${JSON.stringify(pkgJson.dependencies || {})}`);
      console.log(`    js files: ${jsFiles.length}`);
      malFails++;
    } else {
      console.log(`  OK   ${name}: ${findings.length} findings (${findings.map(f => f.id).join(', ')})`);
    }
  } catch (e) {
    console.log(`  ERR  ${name}: ${e.message}`);
    malFails++;
  }
}

const fpRate = (cleanFails / 5 * 100).toFixed(1);
const malDetectRate = ((malTars.length - malFails) / malTars.length * 100).toFixed(1);
console.log(`\n=== Corpus Results ===`);
console.log(`Clean FP rate: ${fpRate}% (${cleanFails}/5 high/crit)`);
console.log(`Mal detect rate: ${malDetectRate}% (${malTars.length - malFails}/${malTars.length})`);

if (Number(fpRate) >= 2) {
  console.log(`FP <2% : FAIL (${fpRate}% exceeds 2%)`);
  process.exit(1);
}
console.log('FP <2% : PASS');
console.log('Test corpus FP <2% PASS');